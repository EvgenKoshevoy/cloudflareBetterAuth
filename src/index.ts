import { Hono } from "hono";
import { cors } from "hono/cors";
import { createAuth } from "./auth";
import type { Env } from "./env";

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

app.use("/api/auth/*", (c, next) => {
  const allowedOrigins = c.env.TRUSTED_ORIGINS
    ? c.env.TRUSTED_ORIGINS.split(",").map((origin) => origin.trim())
    : [];
  return cors({
    origin: allowedOrigins,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })(c, next);
});

app.on(["GET", "POST"], "/api/auth/*", (c) => {
  return getAuth(c.env).handler(c.req.raw);
});

app.get("/health", (c) => c.json({ ok: true }));

export default app;
