# M2M client_credentials + private_key_jwt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let ServiceA obtain an access token scoped to ServiceB from this auth service, authenticating with a private-key-signed JWT assertion instead of a shared secret.

**Architecture:** Mostly configuration of already-installed `better-auth` plugins, plus one small addition. Add the `admin` plugin (role-gates who can register OAuth clients), configure `@better-auth/oauth-provider`'s first-class `resources` entity for ServiceB, and use the plugin's existing `client_credentials` grant + `private_key_jwt` client authentication. One thin passthrough HTTP route is required (Task 3) because the plugin's own client-registration endpoint that accepts `client_credentials_scopes` (`/admin/oauth2/create-client`) is marked `SERVER_ONLY` by the plugin and cannot be called over HTTP at all — verified in the plugin's source (`node_modules/@better-auth/oauth-provider/dist/authorize-Crqw4_bR.mjs:2533`, `metadata: { SERVER_ONLY: true }`). The route does no authorization of its own; it forwards to `auth.api.adminCreateOAuthClient(...)`, which performs the real `clientPrivileges` check. Two dev scripts drive registration and an end-to-end smoke test since the project has no test framework installed and adding one is out of scope.

**Tech Stack:** better-auth 1.7.1, `@better-auth/oauth-provider` ^1.7.1, Drizzle ORM + D1, Hono, `jose` (JWT signing in dev scripts only), Node.js scripts run against `wrangler dev` + D1 local.

**Spec:** `docs/superpowers/specs/2026-08-20-m2m-client-credentials-design.md`

## Global Constraints

- Use the plugin's built-in `client_credentials` grant + `private_key_jwt` — no custom token-issuing code (spec: "Решение").
- ServiceB is identified by an arbitrary string identifier, not a real URL (spec: resource identifier decision).
- `jwks` is static (stored on the client row), not `jwksUri` (spec: component 3).
- ServiceB is never registered as an `oauth_client` — it only validates tokens via `/api/auth/jwks` (spec: component 5).
- The plugin's `auth.api.adminCreateOAuthClient` (backing the `SERVER_ONLY` `/admin/oauth2/create-client` endpoint) is the only way clients get registered with `client_credentials_scopes` set — reached via one thin passthrough route, `POST /api/admin/oauth-clients`, added in Task 3 (spec: component 3, updated).
- `clientPrivileges` requires `role === "admin"` for every OAuth-client action, not just `create` (spec: component 2, updated — no self-service UI exists in this app).
- Only one resource (ServiceB) and one client (ServiceA) in scope — no rights matrix (spec: "Вне объёма").
- First admin user is bootstrapped by hand via direct SQL — no self-service admin promotion flow (spec: component 4).

---

### Task 1: Admin plugin + role-gated client registration

**Files:**
- Modify: `src/db/schema.ts` — add `role`, `banned`, `banReason`, `banExpires` to `user`; add `impersonatedBy` to `session`
- Modify: `src/auth.ts` — add `admin()` plugin, add `clientPrivileges` to `oauthProvider()` config
- Create: `migrations/0002_admin_role.sql` (generated, not hand-written)

**Interfaces:**
- Produces: `user.role: string | null` column, checked by `clientPrivileges` as `user.role === 'admin'`. Later tasks (registration script) depend on being able to set this column directly via SQL.

- [ ] **Step 1: Add admin-plugin fields to the schema**

In `src/db/schema.ts`, add to the `user` table's column object (after `image`, before `createdAt`):

```ts
        role: t.text('role'),
        banned: t.integer('banned', { mode: 'boolean' }),
        banReason: t.text('ban_reason'),
        banExpires: t.integer('ban_expires', { mode: 'timestamp' }),
```

Add to the `session` table's column object (after `userAgent`, before `createdAt`):

```ts
        impersonatedBy: t.text('impersonated_by'),
```

- [ ] **Step 2: Wire the `admin` plugin and the `clientPrivileges` gate**

In `src/auth.ts`, change the plugins import:

```ts
import { admin, jwt } from 'better-auth/plugins';
```

Add `admin()` to the `plugins` array and add `clientPrivileges` to the `oauthProvider({...})` call:

```ts
        plugins: [
            jwt(),
            admin(),
            oauthProvider({
                loginPage: '/sign-in',
                consentPage: '/consent',
                clientPrivileges: async ({ user }) => {
                    // Every OAuth-client administrative action (create, read,
                    // list, update, delete, rotate, configure-scopes) is
                    // restricted to admins. This app has no self-service UI
                    // for OAuth clients, so there's no reason to allow
                    // non-admins any of these actions.
                    return user?.role === 'admin';
                },
            }),
        ],
```

- [ ] **Step 3: Generate and apply the migration**

Run:
```bash
npm run db:generate
```
Expected: a new file `migrations/0002_<name>.sql` is created (drizzle-kit picks the name), plus updated `migrations/meta/0002_snapshot.json` and `migrations/meta/_journal.json`. Open the generated SQL and confirm it only adds columns to `user` and `session` (four `ALTER TABLE user ADD COLUMN ...` plus one on `session`) — no drops, no new tables.

Then apply it:
```bash
npm run db:migrate:local
```
Expected: command exits 0, reports migration `0002_...` applied.

- [ ] **Step 4: Verify the columns exist**

```bash
npx wrangler d1 execute DB --local --command "PRAGMA table_info(user);"
```
Expected: the output rows include `role`, `banned`, `ban_reason`, `ban_expires`.

- [ ] **Step 5: Verify the privilege gate rejects a non-admin session**

Start the dev server in the background:
```bash
npm run dev &
sleep 2
```

Create a regular (non-admin) user and capture its session cookie:
```bash
curl -sS -c /tmp/m2m-cookies.txt -X POST http://localhost:8787/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"nonadmin@test.local","password":"correct horse battery staple","name":"Non Admin"}' | node -e "process.stdin.resume();process.stdin.setEncoding('utf8');let d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>console.log(JSON.parse(d)))"
```
Expected: JSON response with a `user` object, no `role` (defaults to none/`"user"`).

Attempt to register an OAuth client with that session, against the plugin's own session-gated `/oauth2/create-client` endpoint (this is NOT the endpoint real registration will use later — Task 3 adds a passthrough route for that, because the endpoint that actually accepts `client_credentials_scopes`, `/admin/oauth2/create-client`, is `SERVER_ONLY` and unreachable over HTTP at all. This probe only needs to prove `clientPrivileges` blocks a non-admin session, and `clientPrivileges` is checked identically on both endpoints):
```bash
curl -sS -b /tmp/m2m-cookies.txt -o /tmp/m2m-response.json -w '%{http_code}\n' \
  -X POST http://localhost:8787/api/auth/oauth2/create-client \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"probe","grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]}}'
```
Expected: prints `401`. `cat /tmp/m2m-response.json` shows an `UNAUTHORIZED`-style error, confirming `clientPrivileges` blocked the non-admin session before any client was created.

Stop the dev server:
```bash
kill %1
```

- [ ] **Step 6: Commit**

```bash
git add src/db/schema.ts src/auth.ts migrations/
git commit -m "Add admin plugin and gate OAuth client registration to admins"
```

---

### Task 2: ServiceB as a first-class OAuth resource

**Files:**
- Modify: `src/db/schema.ts` — add `oauthResource` and `oauthClientResource` tables
- Modify: `src/auth.ts` — add `resources`, `enforcePerClientResources`, `clientRegistrationDefaultResources` to `oauthProvider()` config
- Modify: `src/env.ts` — add `SERVICE_B_RESOURCE_ID: string`
- Modify: `wrangler.jsonc` — add `SERVICE_B_RESOURCE_ID` to `vars`
- Modify: `.dev.vars.example` — add `SERVICE_B_RESOURCE_ID`
- Create: `migrations/0003_oauth_resource.sql` (generated)

**Interfaces:**
- Consumes: `env.SERVICE_B_RESOURCE_ID` (Task 2's own new env field)
- Produces: an `oauth_resource` row seeded at boot with `identifier = env.SERVICE_B_RESOURCE_ID`; every OAuth client registered via `auth.api.adminCreateOAuthClient` (Task 3's passthrough route) from here on is auto-linked to it via `oauth_client_resource` (through `clientRegistrationDefaultResources`). Task 3's registration script relies on this auto-link — it does not call a separate link endpoint.

- [ ] **Step 1: Add the resource tables to the schema**

In `src/db/schema.ts`, add after the `oauthClientAssertion` table:

```ts
export const oauthResource = sqliteTable('oauth_resource', {
    id: t.text('id').primaryKey(),
    identifier: t.text('identifier').notNull().unique(),
    name: t.text('name').notNull(),
    accessTokenTtl: t.integer('access_token_ttl'),
    refreshTokenTtl: t.integer('refresh_token_ttl'),
    signingAlgorithm: t.text('signing_algorithm'),
    signingKeyId: t.text('signing_key_id'),
    allowedScopes: t.text('allowed_scopes', { mode: 'json' }).$type<string[]>(),
    customClaims: t.text('custom_claims', { mode: 'json' }),
    dpopBoundAccessTokensRequired: t.integer('dpop_bound_access_tokens_required', { mode: 'boolean' }),
    disabled: t.integer('disabled', { mode: 'boolean' }),
    createdAt: t.integer('created_at', { mode: 'timestamp' }),
    updatedAt: t.integer('updated_at', { mode: 'timestamp' }),
    policyVersion: t.integer('policy_version'),
    metadata: t.text('metadata', { mode: 'json' }),
});

export const oauthClientResource = sqliteTable(
    'oauth_client_resource',
    {
        id: t.text('id').primaryKey(),
        clientId: t
            .text('client_id')
            .notNull()
            .references(() => oauthClient.clientId, { onDelete: 'cascade' }),
        resourceId: t
            .text('resource_id')
            .notNull()
            .references(() => oauthResource.id, { onDelete: 'cascade' }),
        metadata: t.text('metadata', { mode: 'json' }),
        createdAt: t.integer('created_at', { mode: 'timestamp' }),
    },
    (table) => [
        t.index('oauth_client_resource_client_id_idx').on(table.clientId),
        t.index('oauth_client_resource_resource_id_idx').on(table.resourceId),
        t.uniqueIndex('oauth_client_resource_client_resource_idx').on(table.clientId, table.resourceId),
    ],
);
```

- [ ] **Step 2: Add `SERVICE_B_RESOURCE_ID` to the env type and config**

In `src/env.ts`, add to the `Env` interface:
```ts
    SERVICE_B_RESOURCE_ID: string;
```

In `wrangler.jsonc`, add to `vars`:
```jsonc
        "SERVICE_B_RESOURCE_ID": "urn:service:serviceb",
```

In `.dev.vars.example`, add a line:
```
SERVICE_B_RESOURCE_ID=urn:service:serviceb
```

Then create your local `.dev.vars` if you haven't already (`cp .dev.vars.example .dev.vars`, fill in `BETTER_AUTH_SECRET`) — this file is gitignored and required for `npm run dev` to work.

- [ ] **Step 3: Configure the resource and its linkage on the plugin**

In `src/auth.ts`, extend the `oauthProvider({...})` call from Task 1 with:

```ts
                resources: [
                    {
                        identifier: env.SERVICE_B_RESOURCE_ID,
                        name: 'ServiceB',
                        allowedScopes: ['serviceb:access'],
                    },
                ],
                enforcePerClientResources: true,
                clientRegistrationDefaultResources: [env.SERVICE_B_RESOURCE_ID],
```

(`enforcePerClientResources: true` is already the plugin default — set explicitly here so the "no client gets a resource it isn't linked to" guarantee is visible in the config, not implied.)

- [ ] **Step 4: Generate and apply the migration**

```bash
npm run db:generate
```
Expected: `migrations/0003_<name>.sql` created with two `CREATE TABLE` statements (`oauth_resource`, `oauth_client_resource`) and their indexes — no other changes.

```bash
npm run db:migrate:local
```
Expected: exits 0.

- [ ] **Step 5: Verify the tables exist**

```bash
npx wrangler d1 execute DB --local --command "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('oauth_resource','oauth_client_resource');"
```
Expected: both table names listed. (Whether the `urn:service:serviceb` row itself is seeded is verified in Task 3 Step 5, once a request has actually gone through the oauth-provider route handler — a plain `wrangler dev` boot with no matching request may not trigger the seed.)

- [ ] **Step 6: Commit**

```bash
git add src/db/schema.ts src/auth.ts src/env.ts wrangler.jsonc .dev.vars.example migrations/
git commit -m "Add ServiceB as a first-class OAuth resource"
```

---

### Task 3: ServiceA client registration script

**Files:**
- Modify: `src/index.ts` — add a thin passthrough route to the `SERVER_ONLY` admin client-registration endpoint
- Create: `scripts/register-service-a.mjs`
- Modify: `package.json` — add `jose` devDependency, add `register:service-a` script
- Modify: `.gitignore` — ignore `scripts/.service-a-credentials.json`

**Interfaces:**
- Consumes: `POST /api/auth/sign-in/email` (admin session cookie), the new `POST /api/admin/oauth-clients` route added in Step 1
- Produces: `scripts/.service-a-credentials.json` — `{ clientId: string, privateKeyJwk: JsonWebKey, publicKeyJwk: JsonWebKey }`, consumed by Task 4's smoke test script.

- [ ] **Step 1: Add the passthrough route to the SERVER_ONLY admin endpoint**

`@better-auth/oauth-provider`'s `POST /admin/oauth2/create-client` — the only endpoint that accepts `client_credentials_scopes` — is registered with `metadata: { SERVER_ONLY: true }` (`node_modules/@better-auth/oauth-provider/dist/authorize-Crqw4_bR.mjs:2533`), meaning better-auth refuses to expose it over HTTP; it can only be invoked from server-side code via `auth.api.adminCreateOAuthClient(...)`. The plain `POST /oauth2/create-client` HTTP endpoint doesn't accept `client_credentials_scopes` in its body schema at all, and a client with no `client_credentials_scopes` can never use the `client_credentials` grant (the plugin throws `unauthorized_client` — see `handleClientCredentialsGrant` in `introspect-6ew7sakf.mjs:2069-2071`). So a passthrough route is required — this is the plan's one exception to "pure configuration, no custom code".

In `src/index.ts`, add (after the existing `/api/auth/*` routes, before `/health`):

```ts
app.post('/api/admin/oauth-clients', async (c) => {
    const auth = getAuth(c.env);
    return auth.api.adminCreateOAuthClient({
        body: await c.req.json(),
        headers: c.req.raw.headers,
        asResponse: true,
    });
});
```

`asResponse: true` makes `auth.api.adminCreateOAuthClient` return a real `Response` (with whatever status `clientPrivileges`/validation produced — 401 for a non-admin session, 201 on success) instead of throwing an `APIError` that Hono would turn into a bare 500. The route does no authorization of its own — `adminCreateOAuthClient` runs the same `clientPrivileges` check from Task 1 using the session found in the forwarded `headers` (the caller's cookie).

- [ ] **Step 2: Verify the route rejects a non-admin session and typechecks**

```bash
npm run typecheck
npm run dev &
sleep 2
curl -sS -c /tmp/m2m-cookies2.txt -X POST http://localhost:8787/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"nonadmin2@test.local","password":"correct horse battery staple","name":"Non Admin 2"}' > /dev/null
curl -sS -b /tmp/m2m-cookies2.txt -o /tmp/m2m-response2.json -w '%{http_code}\n' \
  -X POST http://localhost:8787/api/admin/oauth-clients \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"probe","grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":[]}}'
kill %1
```
Expected: `npm run typecheck` prints no errors. The curl prints `401` — the route reaches the real `SERVER_ONLY` endpoint (not a 404) and `clientPrivileges` still blocks a non-admin session through it.

- [ ] **Step 3: Commit the route**

```bash
git add src/index.ts
git commit -m "Add passthrough route to the SERVER_ONLY admin OAuth client endpoint"
```

- [ ] **Step 4: Add `jose` and a run script**

```bash
npm install --save-dev jose@6.2.9
```

In `package.json`'s `"scripts"`, add:
```json
    "register:service-a": "node scripts/register-service-a.mjs"
```

- [ ] **Step 5: Write the registration script**

Create `scripts/register-service-a.mjs`:

```js
import { generateKeyPair, exportJWK } from 'jose';
import { writeFile } from 'node:fs/promises';

const BASE_URL = process.env.AUTH_BASE_URL ?? 'http://localhost:8787';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (an existing user with role=admin) before running.');
    process.exit(1);
}

async function signIn() {
    const res = await fetch(`${BASE_URL}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    });
    if (!res.ok) {
        throw new Error(`sign-in failed: ${res.status} ${await res.text()}`);
    }
    const setCookie = res.headers.get('set-cookie');
    if (!setCookie) throw new Error('sign-in succeeded but no session cookie was returned');
    return setCookie.split(';')[0];
}

async function registerClient(cookie, publicJwk) {
    const res = await fetch(`${BASE_URL}/api/admin/oauth-clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({
            client_name: 'ServiceA',
            grant_types: ['client_credentials'],
            token_endpoint_auth_method: 'private_key_jwt',
            jwks: { keys: [publicJwk] },
            client_credentials_scopes: ['serviceb:access'],
        }),
    });
    const body = await res.json();
    if (!res.ok) {
        throw new Error(`create-client failed: ${res.status} ${JSON.stringify(body)}`);
    }
    return body;
}

const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
const kid = `service-a-${Date.now()}`;
const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: 'RS256', use: 'sig' };

const cookie = await signIn();
const client = await registerClient(cookie, publicJwk);

await writeFile(
    new URL('./.service-a-credentials.json', import.meta.url),
    JSON.stringify({ clientId: client.client_id, privateKeyJwk: privateJwk, publicKeyJwk: publicJwk }, null, 2),
);

console.log(`Registered ServiceA as client_id=${client.client_id}`);
console.log('Credentials written to scripts/.service-a-credentials.json');
```

- [ ] **Step 6: Ignore the generated credentials file**

Add to `.gitignore`:
```
scripts/.service-a-credentials.json
```

- [ ] **Step 7: Run it end-to-end against local dev**

```bash
npm run dev &
sleep 2

# Bootstrap an admin user (one-time, matches Task 1's manual-promotion decision)
curl -sS -X POST http://localhost:8787/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@test.local","password":"correct horse battery staple","name":"Admin"}' > /dev/null
npx wrangler d1 execute DB --local --command "UPDATE user SET role = 'admin' WHERE email = 'admin@test.local';"

ADMIN_EMAIL=admin@test.local ADMIN_PASSWORD='correct horse battery staple' npm run register:service-a
```
Expected: prints `Registered ServiceA as client_id=...` and writes `scripts/.service-a-credentials.json`.

- [ ] **Step 8: Verify the client row and its resource link**

```bash
npx wrangler d1 execute DB --local --command "SELECT client_id, token_endpoint_auth_method FROM oauth_client;"
npx wrangler d1 execute DB --local --command "SELECT c.client_id, r.identifier FROM oauth_client_resource cr JOIN oauth_client c ON c.client_id = cr.client_id JOIN oauth_resource r ON r.id = cr.resource_id;"
kill %1
```
Expected: first query shows one row with `token_endpoint_auth_method = private_key_jwt`; second query shows that client linked to `urn:service:serviceb` — confirming `clientRegistrationDefaultResources` auto-linked it without a separate call. (Note the join is on `oauth_client.client_id`, the public OAuth client id — `oauth_client_resource.client_id` references that column, not `oauth_client`'s internal `id`.)

- [ ] **Step 9: Commit**

```bash
git add scripts/register-service-a.mjs package.json package-lock.json .gitignore
git commit -m "Add ServiceA OAuth client registration script"
```

---

### Task 4: End-to-end M2M smoke test + docs

**Files:**
- Create: `scripts/m2m-smoke-test.mjs`
- Modify: `package.json` — add `test:m2m` script
- Modify: `README.md` — document the M2M flow

**Interfaces:**
- Consumes: `scripts/.service-a-credentials.json` (Task 3), `POST /api/auth/oauth2/token`, `GET /api/auth/jwks`

- [ ] **Step 1: Write the smoke test script**

Create `scripts/m2m-smoke-test.mjs`:

```js
import { readFile } from 'node:fs/promises';
import { importJWK, SignJWT, createRemoteJWKSet, jwtVerify } from 'jose';

const BASE_URL = process.env.AUTH_BASE_URL ?? 'http://localhost:8787';
const TOKEN_ENDPOINT = `${BASE_URL}/api/auth/oauth2/token`;
const RESOURCE_ID = process.env.SERVICE_B_RESOURCE_ID ?? 'urn:service:serviceb';

const creds = JSON.parse(await readFile(new URL('./.service-a-credentials.json', import.meta.url), 'utf8'));
const privateKey = await importJWK(creds.privateKeyJwk, 'RS256');

let failures = 0;
function check(name, condition) {
    if (condition) {
        console.log(`PASS: ${name}`);
    } else {
        console.error(`FAIL: ${name}`);
        failures += 1;
    }
}

async function signAssertion({ exp, jti } = {}) {
    return new SignJWT({})
        .setProtectedHeader({ alg: 'RS256', kid: creds.privateKeyJwk.kid })
        .setIssuer(creds.clientId)
        .setSubject(creds.clientId)
        .setAudience(TOKEN_ENDPOINT)
        .setJti(jti ?? crypto.randomUUID())
        .setIssuedAt()
        .setExpirationTime(exp ?? '5m')
        .sign(privateKey);
}

async function requestToken({ assertion, resource = RESOURCE_ID }) {
    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_assertion: assertion,
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    });
    if (resource) body.append('resource', resource);
    const res = await fetch(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
    });
    return { status: res.status, body: await res.json() };
}

// 1. Happy path: valid assertion -> access token scoped to ServiceB
const happyAssertion = await signAssertion();
const happy = await requestToken({ assertion: happyAssertion });
check('happy path returns 200', happy.status === 200);
check('happy path returns an access_token', typeof happy.body.access_token === 'string');

if (happy.body.access_token) {
    const jwks = createRemoteJWKSet(new URL(`${BASE_URL}/api/auth/jwks`));
    const { payload } = await jwtVerify(happy.body.access_token, jwks);
    check('access token aud includes ServiceB resource', [].concat(payload.aud).includes(RESOURCE_ID));
    check('access token scope includes serviceb:access', (payload.scope ?? '').split(' ').includes('serviceb:access'));
}

// 2. Replay: reusing the same jti must be rejected
const replayJti = crypto.randomUUID();
const firstUse = await signAssertion({ jti: replayJti });
await requestToken({ assertion: firstUse });
const replayAssertion = await signAssertion({ jti: replayJti });
const replay = await requestToken({ assertion: replayAssertion });
check('replayed jti is rejected', replay.status >= 400);

// 3. Expired assertion must be rejected
const expiredAssertion = await signAssertion({ exp: Math.floor(Date.now() / 1000) - 60 });
const expired = await requestToken({ assertion: expiredAssertion });
check('expired assertion is rejected', expired.status >= 400);

// 4. Unlinked resource must be rejected
const wrongResourceAssertion = await signAssertion();
const wrongResource = await requestToken({ assertion: wrongResourceAssertion, resource: 'urn:service:not-linked' });
check('request for an unlinked resource is rejected', wrongResource.status >= 400);

if (failures > 0) {
    console.error(`${failures} check(s) failed`);
    process.exit(1);
}
console.log('All M2M checks passed');
```

- [ ] **Step 2: Add the run script**

In `package.json`'s `"scripts"`, add:
```json
    "test:m2m": "node scripts/m2m-smoke-test.mjs"
```

- [ ] **Step 3: Run it against local dev (reusing Task 3's registered client)**

```bash
npm run dev &
sleep 2
npm run test:m2m
kill %1
```
Expected: five `PASS:` lines, `All M2M checks passed`, exit code 0. If ServiceA wasn't already registered in this D1 instance, run Task 3's Step 4 first.

- [ ] **Step 4: Document the flow in README**

Append to `README.md` a new section:

```markdown
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
2. Register ServiceA as an OAuth client:
   ```bash
   ADMIN_EMAIL=you@example.com ADMIN_PASSWORD=... npm run register:service-a
   ```
   This generates an RS256 key pair, registers the public half with
   `token_endpoint_auth_method: private_key_jwt`, and writes the private key
   to `scripts/.service-a-credentials.json` (gitignored — treat it like the
   real ServiceA secret in dev; in production ServiceA generates and holds
   its own key, and only the public JWK is sent to this endpoint).

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
`scope` includes the scopes ServiceB requires.

### Smoke test

`npm run test:m2m` drives the whole flow (happy path, replay rejection,
expired-assertion rejection, unlinked-resource rejection) against a local
`wrangler dev` + D1, using the client registered by `register:service-a`.
```

- [ ] **Step 5: Commit**

```bash
git add scripts/m2m-smoke-test.mjs package.json README.md
git commit -m "Add M2M end-to-end smoke test and document the flow"
```
