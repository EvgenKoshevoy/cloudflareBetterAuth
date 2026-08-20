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
