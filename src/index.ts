import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { createAuth } from './auth';
import type { Env } from './env';

// Reuse the better-auth instance across requests within the same isolate -
// building it (route table, hooks, plugins) is not free, and `env` is a
// stable reference for the lifetime of the isolate.
let cached: { env: Env; auth: ReturnType<typeof createAuth> } | undefined;

function getAuth(env: Env) {
    if (!cached || cached.env !== env) {
        cached = { env, auth: createAuth(env) };
    }
    return cached.auth;
}

const app = new Hono<{ Bindings: Env }>();

app.use('/api/auth/*', (c, next) => {
    const allowedOrigins = c.env.TRUSTED_ORIGINS ? c.env.TRUSTED_ORIGINS.split(',').map((origin) => origin.trim()) : [];
    return cors({
        origin: allowedOrigins,
        allowMethods: ['GET', 'POST', 'OPTIONS'],
        allowHeaders: ['Content-Type', 'Authorization'],
        credentials: true,
    })(c, next);
});

app.on(['GET', 'POST'], '/api/auth/*', (c) => {
    return getAuth(c.env).handler(c.req.raw);
});

app.post('/api/admin/oauth-clients', async (c) => {
    // Mirror the CORS/trusted-origin gate already applied to /api/auth/* above.
    // This route sits outside that prefix (it's a thin passthrough to the
    // SERVER_ONLY admin OAuth client endpoint), but it is still driven by an
    // admin's session cookie, and crossSubDomainCookies (see COOKIE_DOMAIN in
    // src/auth.ts) makes any subdomain same-site for cookie purposes. Reject
    // requests carrying an Origin that isn't trusted, when TRUSTED_ORIGINS is
    // configured, so a compromised subdomain can't drive this endpoint with a
    // leaked/stolen admin cookie.
    const allowedOrigins = c.env.TRUSTED_ORIGINS ? c.env.TRUSTED_ORIGINS.split(',').map((origin) => origin.trim()) : [];
    const origin = c.req.header('Origin');
    if (allowedOrigins.length > 0 && origin && !allowedOrigins.includes(origin)) {
        return c.json({ error: 'invalid_request' }, 400);
    }

    let body: Record<string, unknown>;
    try {
        body = await c.req.json();
    } catch {
        return c.json({ error: 'invalid_request' }, 400);
    }

    const auth = getAuth(c.env);
    return auth.api.adminCreateOAuthClient({
        body,
        headers: c.req.raw.headers,
        asResponse: true,
    });
});

app.get('/health', (c) => c.json({ ok: true }));

export default app;
