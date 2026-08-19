export interface Env {
  DB: D1Database;
  SESSION_KV?: KVNamespace;
  BETTER_AUTH_SECRET: string;
  BETTER_AUTH_URL: string;
  TRUSTED_ORIGINS?: string;
  COOKIE_DOMAIN?: string;
}
