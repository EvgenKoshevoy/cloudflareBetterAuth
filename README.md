# cloudflareBetterAuth

Auth service for `imadeit.dev`, built with [Hono](https://hono.dev) + [better-auth](https://www.better-auth.com) on Cloudflare Workers, backed by D1 via Drizzle ORM. Deployed at `auth.imadeit.dev`.

## Stack

- **Hono 4** — router / request handler
- **better-auth 1.7** — auth core (email+password out of the box; add social/OTP/2FA plugins as needed)
- **Drizzle ORM** — typed D1 access, `drizzle-kit` for migrations
- **Cloudflare D1** — database (`ae07e1bc-9646-4481-bcf1-f737e6468860`, bound as `DB`)
- **Wrangler 4** — dev/deploy, custom domain routing

## Performance choices baked in

- **Session cookie cache** (`session.cookieCache`) — most `getSession` calls are verified straight from a signed cookie, no D1 read.
- **better-auth instance memoized per isolate** (`src/index.ts`) — avoids rebuilding the auth route table on every request.
- **No `nodejs_compat`** — better-auth's crypto (`@noble/hashes`, `jose`) runs on WebCrypto, keeping the bundle small and cold starts fast.
- **Explicit indexes** on `session.user_id`, `account.user_id`, `account(provider_id, account_id)`, `verification.identifier` — D1/SQLite doesn't index foreign keys automatically.
- **`transaction: false`** on the Drizzle adapter — D1 doesn't support interactive multi-statement transactions; operations run sequentially instead of failing.
- Optional **KV secondary storage** for sessions/rate-limiting (see below) to take hot reads off D1 entirely.

## Setup

```bash
npm install
cp .dev.vars.example .dev.vars   # fill in a real BETTER_AUTH_SECRET
npm run cf-typegen               # generates worker-configuration.d.ts (gitignored)
```

Generate a secret:

```bash
openssl rand -base64 32
```

### Database

The D1 database already exists. Apply the schema:

```bash
npm run db:migrate:local    # local dev DB
npm run db:migrate:remote   # production D1
```

If `wrangler.jsonc`'s `database_name` (`imadeit-auth-db`) doesn't match your actual D1 database name, update it — the `database_id` is already correct.

If you change `src/db/schema.ts` later (e.g. after adding a better-auth plugin
with extra fields/tables), update the schema by hand to match, then generate
the SQL migration with:

```bash
npm run db:generate
```

(`@better-auth/cli`, which used to auto-generate this schema, is deprecated
upstream and pinned to an old better-auth version — don't add it back without
checking it's been replaced.)

### Secrets

```bash
wrangler secret put BETTER_AUTH_SECRET
```

`BETTER_AUTH_URL` and `TRUSTED_ORIGINS` are plain vars in `wrangler.jsonc` — update `TRUSTED_ORIGINS` to match whatever origins call this auth server.

### Custom domain

`wrangler.jsonc` already routes `auth.imadeit.dev` to this worker via `custom_domain: true`. On first deploy, Cloudflare provisions the domain automatically as long as `imadeit.dev` is on the same account/zone.

### Optional: KV-backed session cache

For high-traffic setups, offload session storage to KV so most reads skip D1:

```bash
wrangler kv namespace create SESSION_KV
```

Uncomment the `kv_namespaces` block in `wrangler.jsonc` with the returned id. `src/auth.ts` picks it up automatically (`secondaryStorage` + KV-backed rate limiting) when the binding is present — no other code changes needed.

## Development

```bash
npm run dev          # wrangler dev, local D1
npm run cf-typegen   # regenerate worker-configuration.d.ts from wrangler.jsonc
npm run typecheck
```

## Deploy

```bash
npm run deploy
```

## Endpoints

- `GET/POST /api/auth/*` — better-auth handler (sign-up, sign-in, sessions, etc.)
- `POST /api/admin/oauth-clients` — admin-only passthrough to the OAuth client registration endpoint (see [M2M authorization](#m2m-authorization-service-to-service) below)
- `POST /api/admin/oauth-resources` / `GET /api/admin/oauth-resources` — admin-only passthrough to create/list OAuth resources (RFC 8707 protected resources; see [M2M authorization](#m2m-authorization-service-to-service) below)
- `GET/PATCH/DELETE /api/admin/oauth-resources/:identifier` — admin-only passthrough to read/update/delete a single OAuth resource
- `POST/DELETE /api/admin/oauth-resources/:identifier/clients/:client_id` — admin-only passthrough to link/unlink a client to a resource
- `GET /health` — liveness check

The `admin` plugin also exposes better-auth's full admin API (list-users,
set-role, ban-user, impersonate-user, and more) under `/api/auth/admin/*`,
not just the `role` field this project uses for the OAuth-client gate above —
grant the `admin` role accordingly, since it carries more privilege than
"can register OAuth clients."

## Client usage

From the app(s) on `imadeit.dev`, use `better-auth/client`:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "https://auth.imadeit.dev",
});
```

Cross-subdomain cookies are enabled (`advanced.crossSubDomainCookies`, domain `.imadeit.dev`), so a session issued by `auth.imadeit.dev` is valid on `imadeit.dev` and its other subdomains.

## M2M authorization (service-to-service)

A calling service authenticates to this auth service with a JWT it signs with
its own private key (RFC 7523 `private_key_jwt`), and receives an access
token scoped to a target service via OAuth2 `client_credentials` (RFC 8707
`resource` parameter). No shared secrets are involved.

Two concepts, both admin-API-driven, nothing seeded at boot — this service
has no built-in knowledge of any particular resource or client; every one is
created by hand through the endpoints below and lives only in the database:

- **OAuth resource** — the *target* service being called. An RFC 8707
  protected resource: an `identifier` plus policy (`allowedScopes`, TTLs,
  whether it's `disabled`, etc.).
- **OAuth client** — the *calling* service. Registered with
  `token_endpoint_auth_method: private_key_jwt` and its public JWK.

A client only receives tokens for resources it's explicitly **linked** to
(`enforcePerClientResources: true` in `src/auth.ts`) — creating a resource and
a client doesn't implicitly connect them.

**Scopes are the one exception to "fully API-driven."** The plugin checks
every `client_credentials_scopes` value a client registers with against a
fixed allow-list (`oauthProvider({ scopes: [...] })` in `src/auth.ts`) — that
list is read once at deploy time, not from the database, and there's no admin
endpoint that can extend it (verified against the plugin's source: the
allow-list is captured into a private closure inside `oauthProvider(...)` and
never re-read afterward). To keep resource/client management API-driven
anyway, `src/auth.ts` ships a fixed, resource-agnostic CRUD vocabulary —
`m2m:create`, `m2m:read`, `m2m:update`, `m2m:delete` — that every resource's
`allowedScopes` and every client's `client_credentials_scopes` draws a subset
from. A new resource never needs a code change to use these four; only
introducing a genuinely *new* scope name beyond them does (edit `scopes` in
`src/auth.ts` and redeploy).

### 0. Get an admin session

Every `/api/admin/*` route below needs an admin session cookie and, when
`TRUSTED_ORIGINS` is set, a matching `Origin` header.

```bash
# One-time: create a user, then promote it to admin directly in D1
# (no self-service promotion exists).
npx wrangler d1 execute DB --local --command \
  "UPDATE user SET role = 'admin' WHERE email = 'you@example.com';"

# Sign in and capture the session cookie for the calls below.
COOKIE=$(curl -s -i -X POST https://auth.imadeit.dev/api/auth/sign-in/email \
  -H 'Content-Type: application/json' -H 'Origin: https://imadeit.dev' \
  -d '{"email":"you@example.com","password":"..."}' \
  | grep -i '^set-cookie' | sed 's/^[Ss]et-[Cc]ookie: //' | cut -d';' -f1 | paste -sd '; ' -)
```

### 1. Create the target service's resource

```bash
curl -X POST https://auth.imadeit.dev/api/admin/oauth-resources \
  -H 'Content-Type: application/json' -H "Cookie: $COOKIE" -H 'Origin: https://imadeit.dev' \
  -d '{
    "identifier": "<resource-identifier>",
    "name": "<human-readable name>",
    "allowedScopes": ["m2m:read"]
  }'
```

`identifier` is the RFC 8707 `resource` value callers will request and the
`aud` claim issued tokens will carry — any absolute-URI-shaped string works
(e.g. `urn:example:my-api`), it doesn't have to resolve. `allowedScopes` caps
which of the fixed `m2m:*` scopes (see above) a linked client may be granted
for this resource specifically — pick whichever subset it needs.

### 2. Register the calling service as an OAuth client

```bash
curl -X POST https://auth.imadeit.dev/api/admin/oauth-clients \
  -H 'Content-Type: application/json' -H "Cookie: $COOKIE" -H 'Origin: https://imadeit.dev' \
  -d '{
    "client_name": "<calling service name>",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "private_key_jwt",
    "jwks": { "keys": [ <calling service public JWK> ] },
    "client_credentials_scopes": ["m2m:read"]
  }'
```

Returns `client_id` (and the rest of the registered client record). The
calling service generates its own RS256/ES256 key pair and holds the private
key itself — only the public JWK is ever sent here. `jwks` above is a static
key set; use `jwks_uri` instead if the service can host its own JWKS and
wants to rotate keys without re-registering.

### 3. Link the client to the resource

```bash
curl -X POST "https://auth.imadeit.dev/api/admin/oauth-resources/<resource-identifier>/clients/$CLIENT_ID" \
  -H "Cookie: $COOKIE" -H 'Origin: https://imadeit.dev'
```

No body — both identifiers are in the path. Re-linking an already-linked pair
is a no-op (`{"linked":true,"alreadyLinked":true}`), so this is safe to retry.

### Managing resources and links later

- `GET /api/admin/oauth-resources` — list all resources
- `GET /api/admin/oauth-resources/:identifier` — read one
- `PATCH /api/admin/oauth-resources/:identifier` — update policy (e.g.
  `{"disabled": true}` to kill a resource without deleting it, or change
  `allowedScopes`)
- `DELETE /api/admin/oauth-resources/:identifier` — delete a resource
- `DELETE /api/admin/oauth-resources/:identifier/clients/:client_id` — unlink
  a client from a resource (revokes its ability to request that `resource`
  going forward; existing tokens already issued aren't retroactively revoked)

All of the above require the same admin cookie + `Origin` header as steps 1–3.

### Requesting a token (what the calling service does in production)

```bash
curl -X POST https://auth.imadeit.dev/api/auth/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_assertion=$SIGNED_JWT" \
  --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  --data-urlencode 'resource=<resource-identifier>'
```

`$SIGNED_JWT` is a JWT signed with the calling service's private key:
`iss`/`sub` = its registered `client_id`, `aud` = the token endpoint URL,
`exp` within 5 minutes, and a unique `jti` (each `jti` may be used once —
replays are rejected).

### Validating the token (what the target service does)

Fetch `https://auth.imadeit.dev/api/auth/jwks`, verify the access token's
signature against it, and check `aud` includes its own resource identifier
and `scope` includes whatever it requires. Also check that `sub` equals the
calling client's `client_id`: `client_credentials` (M2M) tokens set `sub` to
the client id, while user-delegated tokens (authorization-code /
refresh-token grants) set `sub` to the user id — `aud` + `scope` alone can't
distinguish a genuine M2M token from a user-delegated one that happens to
carry the same scope and resource.
