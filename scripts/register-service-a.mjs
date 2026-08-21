import { generateKeyPair, exportJWK } from 'jose';
import { writeFile } from 'node:fs/promises';

const BASE_URL = process.env.AUTH_BASE_URL ?? 'http://localhost:8787';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
// Node's built-in fetch (undici) sends `Sec-Fetch-Mode: cors` on every
// request, which trips better-auth's CSRF check into requiring a trusted
// Origin header (curl and browser same-origin requests don't hit this).
// Must match an entry in TRUSTED_ORIGINS.
const ORIGIN = process.env.AUTH_ORIGIN ?? 'http://localhost:3000';

// Fixture identifiers shared with scripts/m2m-smoke-test.mjs. Nothing is
// seeded at boot (see src/auth.ts) - this script is the one-time "manual"
// creation step for both resources, run through the same admin API a human
// operator would use.
const RESOURCE_ID = 'urn:service:serviceb';
const UNLINKED_TEST_RESOURCE_ID = 'urn:service:unlinked-test';

if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
    console.error('Set ADMIN_EMAIL and ADMIN_PASSWORD (an existing user with role=admin) before running.');
    process.exit(1);
}

async function signIn() {
    const res = await fetch(`${BASE_URL}/api/auth/sign-in/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: ORIGIN },
        body: JSON.stringify({ email: ADMIN_EMAIL, password: ADMIN_PASSWORD }),
    });
    if (!res.ok) {
        throw new Error(`sign-in failed: ${res.status} ${await res.text()}`);
    }
    // Use getSetCookie() (standard in Node 18.16+; this project targets
    // Node 24) rather than headers.get('set-cookie'): Node's fetch (undici)
    // joins multiple Set-Cookie headers with ", " under get(), which is not
    // safely splittable back into individual cookies (cookie values can
    // legally contain commas). better-auth's cookie-cache can set more than
    // one Set-Cookie header (session token + cached session data), so a
    // single-cookie assumption silently drops the second one.
    const setCookies = res.headers.getSetCookie();
    if (!setCookies.length) throw new Error('sign-in succeeded but no session cookie was returned');
    return setCookies.map((cookie) => cookie.split(';')[0]).join('; ');
}

// Idempotent: checks first rather than relying on the create endpoint's
// conflict response, so the script can be run more than once.
async function createResource(cookie, { identifier, name, allowedScopes }) {
    const existing = await fetch(`${BASE_URL}/api/admin/oauth-resources/${encodeURIComponent(identifier)}`, {
        headers: { Cookie: cookie, Origin: ORIGIN },
    });
    if (existing.ok) {
        console.log(`Resource ${identifier} already exists, skipping`);
        return;
    }

    const res = await fetch(`${BASE_URL}/api/admin/oauth-resources`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: ORIGIN },
        body: JSON.stringify({ identifier, name, allowedScopes }),
    });
    if (!res.ok) {
        throw new Error(`create-resource failed: ${res.status} ${JSON.stringify(await res.json())}`);
    }
    console.log(`Created resource ${identifier}`);
}

async function linkClientResource(cookie, identifier, clientId) {
    const res = await fetch(`${BASE_URL}/api/admin/oauth-resources/${encodeURIComponent(identifier)}/clients/${encodeURIComponent(clientId)}`, {
        method: 'POST',
        headers: { Cookie: cookie, Origin: ORIGIN },
    });
    const body = await res.json();
    if (!res.ok) {
        throw new Error(`link-client-resource failed: ${res.status} ${JSON.stringify(body)}`);
    }
}

async function registerClient(cookie, publicJwk) {
    const res = await fetch(`${BASE_URL}/api/admin/oauth-clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: cookie, Origin: ORIGIN },
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

await createResource(cookie, { identifier: RESOURCE_ID, name: 'ServiceB', allowedScopes: ['serviceb:access'] });
// Deliberately left unlinked below - scripts/m2m-smoke-test.mjs uses this to
// exercise enforcePerClientResources's per-client linkage check against a
// resource that genuinely exists but no client is ever linked to.
await createResource(cookie, { identifier: UNLINKED_TEST_RESOURCE_ID, name: 'Unlinked Test Resource (no client should ever be linked to this)', allowedScopes: [] });

const client = await registerClient(cookie, publicJwk);
await linkClientResource(cookie, RESOURCE_ID, client.client_id);

await writeFile(
    new URL('./.service-a-credentials.json', import.meta.url),
    JSON.stringify({ clientId: client.client_id, privateKeyJwk: privateJwk, publicKeyJwk: publicJwk }, null, 2),
);

console.log(`Registered ServiceA as client_id=${client.client_id}, linked to ${RESOURCE_ID}`);
console.log('Credentials written to scripts/.service-a-credentials.json');
