import { betterAuth } from 'better-auth';
import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { admin, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { createDb } from './db';
import * as schema from './db/schema';
import type { Env } from './env';

export function createAuth(env: Env) {
    const db = createDb(env.DB);

    return betterAuth({
        baseURL: env.BETTER_AUTH_URL,
        secret: env.BETTER_AUTH_SECRET,
        trustedOrigins: env.TRUSTED_ORIGINS ? env.TRUSTED_ORIGINS.split(',').map((origin) => origin.trim()) : [],
        database: drizzleAdapter(db, {
            provider: 'sqlite',
            schema,
            transaction: false,
        }),
        emailAndPassword: {
            enabled: true,
        },
        session: {
            cookieCache: {
                enabled: true,
                maxAge: 5 * 60,
            },
            expiresIn: 60 * 60 * 24 * 7,
            updateAge: 60 * 60 * 24,
        },
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
                // Mirrors clientPrivileges: every OAuth-resource administrative
                // action (create, read, list, update, delete, link, unlink) is
                // restricted to admins. Resources are no longer seeded from
                // config (see resources removal below) - this is the only gate
                // controlling who can create them.
                resourcePrivileges: async ({ user }) => {
                    return user?.role === 'admin';
                },
                // The plugin's own `scopes` allow-list gates every
                // client_credentials_scopes value at registration time
                // (validateClientCredentialsScopes in
                // @better-auth/oauth-provider/dist/introspect-*.mjs checks
                // each requested scope against this exact array) - it's fixed
                // at deploy time, not DB-driven, so it can't be extended
                // through the admin API. The four m2m:* scopes below are a
                // generic CRUD vocabulary, deliberately not named after any
                // particular resource: every resource created via
                // POST /api/admin/oauth-resources picks whichever subset it
                // needs for its own `allowedScopes` (e.g. a read-only
                // resource might allow only 'm2m:read'), and every client's
                // `client_credentials_scopes` is likewise a subset of these -
                // both fully API-driven from here on. Only introducing a
                // genuinely new scope literal (a fifth one, beyond this
                // fixed CRUD set) requires editing this array and
                // redeploying.
                scopes: ['openid', 'profile', 'email', 'offline_access', 'm2m:create', 'm2m:read', 'm2m:update', 'm2m:delete'],
                // Newly registered clients (dynamic registration and any future
                // non-admin registration path) get this as their default
                // delegated-scope ceiling instead of the full `scopes` list
                // above. Deliberately excludes the m2m:* scopes: they must stay
                // in the master `scopes` allow-list (client_credentials_scopes
                // validation checks against it independently, see
                // validateClientCredentialsScopes in
                // @better-auth/oauth-provider/dist/introspect-*.mjs), but must
                // NOT be a default capability for a newly registered client -
                // otherwise a future browser-facing authorization-code client,
                // registered through the same client-creation path, could
                // request an m2m:* scope with user consent and receive a token
                // indistinguishable from a genuine M2M client_credentials token.
                clientRegistrationDefaultScopes: ['openid', 'profile', 'email', 'offline_access'],
                // No config-seeded resources and no auto-linking: every
                // resource and every client-resource link is created by hand
                // through the admin API (POST /api/admin/oauth-resources and
                // its /clients/:client_id link route in src/index.ts).
                enforcePerClientResources: true,
            }),
        ],
        ...(env.COOKIE_DOMAIN
            ? {
                  advanced: {
                      crossSubDomainCookies: {
                          enabled: true,
                          domain: env.COOKIE_DOMAIN,
                      },
                  },
              }
            : {}),
        ...(env.SESSION_KV
            ? {
                  // Optional: when bound, better-auth stores sessions in KV
                  // instead of the D1 `session` table entirely (see
                  // `session.storeSessionInDatabase` to keep both). Only active
                  // when SESSION_KV is bound. Note: KV has no atomic
                  // get-and-delete/increment, so
                  // getAndDelete/increment below are best-effort, not race-free -
                  // fine for session caching and coarse rate limiting, not for
                  // anything that needs a hard, exact limit under heavy concurrency
                  // (use a Durable Object for that instead).
                  secondaryStorage: {
                      get: (key: string) => env.SESSION_KV!.get(key),
                      set: (key: string, value: string, ttl?: number) => env.SESSION_KV!.put(key, value, ttl ? { expirationTtl: ttl } : undefined),
                      delete: (key: string) => env.SESSION_KV!.delete(key),
                      getAndDelete: async (key: string) => {
                          const value = await env.SESSION_KV!.get(key);
                          if (value !== null) await env.SESSION_KV!.delete(key);
                          return value;
                      },
                      increment: async (key: string, ttl: number) => {
                          const current = await env.SESSION_KV!.get(key);
                          const next = (current ? Number.parseInt(current, 10) : 0) + 1;
                          await env.SESSION_KV!.put(key, String(next), current ? undefined : { expirationTtl: ttl });
                          return next;
                      },
                  },
                  rateLimit: {
                      storage: 'secondary-storage' as const,
                  },
              }
            : {}),
    });
}

export type Auth = ReturnType<typeof createAuth>;
