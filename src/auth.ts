import { betterAuth } from 'better-auth';
import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { admin, jwt } from 'better-auth/plugins';
import { oauthProvider } from '@better-auth/oauth-provider';
import { sql } from 'drizzle-orm';
import { createDb } from './db';
import type { Db } from './db';
import * as schema from './db/schema';
import type { Env } from './env';

// Baseline scopes independent of any resource - always valid regardless of
// what's in the oauth_resource table. Resource-specific scopes (e.g.
// 'orders:read') are added dynamically, see refreshOAuthScopes below.
const BASE_OAUTH_SCOPES = ['openid', 'profile', 'email', 'offline_access'];

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
                // each requested scope against this exact array), and it's
                // read fresh off this array reference on every request - it
                // is NOT re-evaluated when this factory runs. Started here
                // with just the OIDC baseline; refreshOAuthScopes (below)
                // mutates this array in place once oauth_resource rows exist,
                // so a resource can introduce its own scope literals (e.g.
                // 'orders:read') through the admin API with no code change
                // or redeploy.
                scopes: [...BASE_OAUTH_SCOPES],
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

// `auth.options` is the exact config object passed to betterAuth() above
// (see better-auth's `Auth<Options>` type), so `auth.options.plugins`
// contains the very oauthProvider(...) instance created in createAuth. That
// instance exposes its normalized options as `.options` (see
// @better-auth/oauth-provider/dist/authorize-*.mjs, `return { id:
// "oauth-provider", options: opts, ... }`) - undocumented, but it's the same
// object every endpoint closure in the plugin reads `scopes` from on every
// request. Mutating `.options.scopes` in place therefore takes effect
// immediately for this isolate, with no betterAuth() rebuild.
function findOAuthProviderPlugin(auth: Auth) {
    const plugins = auth.options.plugins as { id: string; options?: { scopes?: string[] } }[] | undefined;
    return plugins?.find((plugin) => plugin.id === 'oauth-provider');
}

async function computeOAuthResourceScopes(db: Db): Promise<string[]> {
    const rows = await db.select({ allowedScopes: schema.oauthResource.allowedScopes }).from(schema.oauthResource);
    return rows.flatMap((row) => row.allowedScopes ?? []);
}

type OAuthResourceFingerprint = { count: number; maxUpdatedAt: number | null };

async function getOAuthResourceFingerprint(db: Db): Promise<OAuthResourceFingerprint> {
    const [row] = await db
        .select({
            count: sql<number>`count(*)`,
            maxUpdatedAt: sql<number | null>`max(${schema.oauthResource.updatedAt})`,
        })
        .from(schema.oauthResource);
    return { count: row?.count ?? 0, maxUpdatedAt: row?.maxUpdatedAt ?? null };
}

// Per-isolate cache of the last fingerprint this auth instance was refreshed
// against, keyed by the instance itself so it's naturally scoped to its
// lifetime (matches the `cached` singleton in src/index.ts - one auth
// instance per isolate).
const oauthScopeFingerprints = new WeakMap<Auth, OAuthResourceFingerprint>();

/**
 * Recomputes the oauth-provider's master `scopes` allow-list from the
 * current oauth_resource rows whenever the table has actually changed
 * (cheap COUNT + MAX(updated_at) check), replacing - not appending to - the
 * live array so scopes removed from a resource's `allowedScopes`, or from a
 * deleted resource, also disappear from the master list on the next request.
 *
 * Known gap: COUNT + MAX(updated_at) won't detect a delete and an unrelated
 * update landing in the same tick that happen to reproduce the previous
 * count and max - vanishingly unlikely for admin-driven resource CRUD, and
 * self-heals on the next real change, so not worth a version counter.
 */
export async function refreshOAuthScopes(auth: Auth, env: Env): Promise<void> {
    const db = createDb(env.DB);
    const fingerprint = await getOAuthResourceFingerprint(db);
    const previous = oauthScopeFingerprints.get(auth);
    if (previous && previous.count === fingerprint.count && previous.maxUpdatedAt === fingerprint.maxUpdatedAt) {
        return;
    }

    const plugin = findOAuthProviderPlugin(auth);
    if (plugin?.options?.scopes) {
        const resourceScopes = await computeOAuthResourceScopes(db);
        const nextScopes = [...new Set([...BASE_OAUTH_SCOPES, ...resourceScopes])];
        plugin.options.scopes.length = 0;
        plugin.options.scopes.push(...nextScopes);
    }
    oauthScopeFingerprints.set(auth, fingerprint);
}
