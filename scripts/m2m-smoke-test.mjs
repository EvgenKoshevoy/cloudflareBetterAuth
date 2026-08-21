import { readFile } from 'node:fs/promises';
import { importJWK, SignJWT, createRemoteJWKSet, jwtVerify } from 'jose';

const BASE_URL = process.env.AUTH_BASE_URL ?? 'http://localhost:8787';
const TOKEN_ENDPOINT = `${BASE_URL}/api/auth/oauth2/token`;
// Must match the identifier scripts/register-service-a.mjs created and
// linked ServiceA to via the admin API - nothing is seeded at boot.
const RESOURCE_ID = 'urn:service:serviceb';

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

// 2. Replay: reusing the same jti must be rejected. Assert the *first* use
// actually succeeded before attempting the replay - otherwise a first
// request that failed for an unrelated reason would make the "replay
// rejected" check below pass vacuously (the second request would also be
// rejected, but not because it was a replay).
const replayJti = crypto.randomUUID();
const firstUse = await signAssertion({ jti: replayJti });
const firstUseResult = await requestToken({ assertion: firstUse });
check('replay scenario: first use of the jti succeeds', firstUseResult.status === 200);
const replayAssertion = await signAssertion({ jti: replayJti });
const replay = await requestToken({ assertion: replayAssertion });
// Verified empirically against a running server: the plugin reports jti
// reuse as invalid_client ("client assertion jti has already been used"),
// not invalid_grant.
check('replayed jti is rejected with invalid_client', replay.body.error === 'invalid_client');
check('replayed jti response has no access_token', replay.body.access_token === undefined);

// 3. Expired assertion must be rejected. Verified empirically: the plugin's
// JWT verification (via jose) surfaces an expired `exp` claim as a generic
// signature-verification failure - invalid_client, not a distinct
// "expired" code - so that's what we assert against, not a guess.
const expiredAssertion = await signAssertion({ exp: Math.floor(Date.now() / 1000) - 60 });
const expired = await requestToken({ assertion: expiredAssertion });
check('expired assertion is rejected with invalid_client', expired.body.error === 'invalid_client');
check('expired assertion response has no access_token', expired.body.access_token === undefined);

// 4. Resource the client is genuinely not linked to must be rejected. This
// targets 'urn:service:unlinked-test', a resource that scripts/register-
// service-a.mjs creates via the admin API (so it exists) but deliberately
// never links any client to. This is what actually exercises
// enforcePerClientResources's per-client linkage check - unlike requesting a
// resource identifier that doesn't exist at all, which would instead be
// rejected earlier by the "resource doesn't exist" check and never reach the
// linkage check.
const wrongResourceAssertion = await signAssertion();
const wrongResource = await requestToken({ assertion: wrongResourceAssertion, resource: 'urn:service:unlinked-test' });
// Verified empirically against a running server: enforcePerClientResources
// rejections use invalid_target, per RFC 8707.
check('request for an unlinked-but-existing resource is rejected with invalid_target', wrongResource.body.error === 'invalid_target');
check('unlinked-resource response has no access_token', wrongResource.body.access_token === undefined);

if (failures > 0) {
    console.error(`${failures} check(s) failed`);
    process.exit(1);
}
console.log('All M2M checks passed');
