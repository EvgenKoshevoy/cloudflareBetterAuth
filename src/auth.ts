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
                resources: [
                    {
                        identifier: env.SERVICE_B_RESOURCE_ID,
                        name: 'ServiceB',
                        allowedScopes: ['serviceb:access'],
                    },
                ],
                enforcePerClientResources: true,
                clientRegistrationDefaultResources: [env.SERVICE_B_RESOURCE_ID],
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
