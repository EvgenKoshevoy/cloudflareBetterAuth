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

ServiceA authenticates to this auth service with a JWT it signs with its own
private key (RFC 7523 `private_key_jwt`), and receives an access token scoped
to ServiceB via OAuth2 `client_credentials` (RFC 8707 `resource` parameter).
No shared secrets are involved.

### One-time setup

1. Create a normal user via `/api/auth/sign-up/email`, then promote it to
   admin directly in D1 (no self-service promotion exists):
   ```bash
   npx wrangler d1 execute DB --local --command \
     "UPDATE user SET role = 'admin' WHERE email = 'you@example.com';"
   ```
2. Register ServiceA as an OAuth client and its resource:
   ```bash
   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=... npm run register:service-a
   ```
   Nothing is seeded at boot — this script does the whole one-time setup by
   hand through the admin API: creates the `urn:service:serviceb` OAuth
   resource, generates an RS256 key pair for ServiceA, registers it with
   `token_endpoint_auth_method: private_key_jwt` (writing the private key to
   `scripts/.service-a-credentials.json`, gitignored — treat it like the real
   ServiceA secret in dev; in production ServiceA generates and holds its own
   key, and only the public JWK is sent to this endpoint), and links the new
   client to the resource via `POST /api/admin/oauth-resources/:identifier/clients/:client_id`.
   A client only gets tokens for resources it's explicitly linked to
   (`enforcePerClientResources`) — use the same admin endpoints to create and
   link any other resource/client pair.

### Requesting a token (what ServiceA does in production)

```bash
curl -X POST https://auth.imadeit.dev/api/auth/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode "client_assertion=$SIGNED_JWT" \
  --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
  --data-urlencode 'resource=urn:service:serviceb'
```

`$SIGNED_JWT` is a JWT signed with ServiceA's private key: `iss`/`sub` =
ServiceA's `client_id`, `aud` = the token endpoint URL, `exp` within 5
minutes, and a unique `jti` (each `jti` may be used once).

### Validating the token (what ServiceB does)

Fetch `https://auth.imadeit.dev/api/auth/jwks`, verify the access token's
signature against it, and check `aud` includes `urn:service:serviceb` and
`scope` includes the scopes ServiceB requires. Also check that `sub` equals
ServiceA's registered `client_id`: `client_credentials` (M2M) tokens set `sub`
to the client id, while user-delegated tokens (authorization-code /
refresh-token grants) set `sub` to the user id — `aud` + `scope` alone
can't distinguish a genuine M2M token from a user-delegated one that happens
to carry the same scope and resource.

### Smoke test

`npm run test:m2m` drives the whole flow (happy path, replay rejection,
expired-assertion rejection, unlinked-resource rejection) against a local
`wrangler dev` + D1, using the client registered by `register:service-a`.
