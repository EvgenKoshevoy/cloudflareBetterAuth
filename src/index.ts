import { Hono } from 'hono';
import type { Context } from 'hono';
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

// Shared guard for every /api/admin/* passthrough route below. Each of these
// routes is a thin forward to a SERVER_ONLY better-auth endpoint (the plugin
// refuses to route them over HTTP itself), driven by an admin's session
// cookie. crossSubDomainCookies (see COOKIE_DOMAIN in src/auth.ts) makes any
// subdomain same-site for cookie purposes, so when TRUSTED_ORIGINS is
// configured this requires a matching Origin header - a missing Origin is
// rejected too (not just a mismatched one), so a compromised subdomain can't
// drive an admin action with a leaked/stolen admin cookie by simply omitting
// the header. Only the Cookie header is forwarded to the plugin call - that's
// all its session lookup needs - so this passthrough can't relay anything
// else to the plugin unexamined.
async function adminPassthrough(c: Context<{ Bindings: Env }>, call: (headers: Headers, body: unknown) => Promise<Response>) {
    const allowedOrigins = c.env.TRUSTED_ORIGINS ? c.env.TRUSTED_ORIGINS.split(',').map((origin) => origin.trim()) : [];
    const origin = c.req.header('Origin');
    if (allowedOrigins.length > 0 && (!origin || !allowedOrigins.includes(origin))) {
        return c.json({ error: 'invalid_request' }, 400);
    }

    // Link/unlink carry no body (path params carry the identifiers) - only
    // attempt to parse one when the caller actually sent one.
    let body: unknown;
    const raw = await c.req.text();
    if (raw) {
        try {
            body = JSON.parse(raw);
        } catch {
            return c.json({ error: 'invalid_request' }, 400);
        }
    }

    const cookie = c.req.header('Cookie');
    const forwardedHeaders = new Headers();
    if (cookie) forwardedHeaders.set('Cookie', cookie);

    return call(forwardedHeaders, body);
}

app.post('/api/admin/oauth-clients', (c) =>
    adminPassthrough(c, (headers, body) =>
        getAuth(c.env).api.adminCreateOAuthClient({
            body: body as Record<string, unknown>,
            headers,
            asResponse: true,
        }),
    ),
);

app.post('/api/admin/oauth-resources', (c) =>
    adminPassthrough(c, (headers, body) =>
        // `identifier` is required by the endpoint's own zod schema (enforced
        // at runtime, returning a 400 when absent) but the body arriving here
        // is unvalidated client JSON - cast past the stricter compile-time
        // shape rather than duplicating that schema in this thin passthrough.
        getAuth(c.env).api.adminCreateOAuthResource({
            body: body as { identifier: string },
            headers,
            asResponse: true,
        }),
    ),
);

app.get('/api/admin/oauth-resources', (c) =>
    adminPassthrough(c, (headers) =>
        getAuth(c.env).api.adminListOAuthResources({
            headers,
            asResponse: true,
        }),
    ),
);

app.get('/api/admin/oauth-resources/:identifier', (c) =>
    adminPassthrough(c, (headers) =>
        getAuth(c.env).api.adminGetOAuthResource({
            params: { identifier: c.req.param('identifier') },
            headers,
            asResponse: true,
        }),
    ),
);

app.patch('/api/admin/oauth-resources/:identifier', (c) =>
    adminPassthrough(c, (headers, body) =>
        getAuth(c.env).api.adminUpdateOAuthResource({
            params: { identifier: c.req.param('identifier') },
            body: body as Record<string, unknown>,
            headers,
            asResponse: true,
        }),
    ),
);

app.delete('/api/admin/oauth-resources/:identifier', (c) =>
    adminPassthrough(c, (headers) =>
        getAuth(c.env).api.adminDeleteOAuthResource({
            params: { identifier: c.req.param('identifier') },
            headers,
            asResponse: true,
        }),
    ),
);

app.post('/api/admin/oauth-resources/:identifier/clients/:client_id', (c) =>
    adminPassthrough(c, (headers) =>
        getAuth(c.env).api.adminLinkClientResource({
            params: { identifier: c.req.param('identifier'), client_id: c.req.param('client_id') },
            headers,
            asResponse: true,
        }),
    ),
);

app.delete('/api/admin/oauth-resources/:identifier/clients/:client_id', (c) =>
    adminPassthrough(c, (headers) =>
        getAuth(c.env).api.adminUnlinkClientResource({
            params: { identifier: c.req.param('identifier'), client_id: c.req.param('client_id') },
            headers,
            asResponse: true,
        }),
    ),
);

app.get('/health', (c) => c.json({ ok: true }));

export default app;
