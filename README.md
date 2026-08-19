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
- `GET /health` — liveness check

## Client usage

From the app(s) on `imadeit.dev`, use `better-auth/client`:

```ts
import { createAuthClient } from "better-auth/client";

export const authClient = createAuthClient({
  baseURL: "https://auth.imadeit.dev",
});
```

Cross-subdomain cookies are enabled (`advanced.crossSubDomainCookies`, domain `.imadeit.dev`), so a session issued by `auth.imadeit.dev` is valid on `imadeit.dev` and its other subdomains.
