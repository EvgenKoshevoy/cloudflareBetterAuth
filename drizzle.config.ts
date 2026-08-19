import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  driver: "d1-http",
  schema: "./src/db/schema.ts",
  out: "./migrations",
  dbCredentials: {
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID!,
    databaseId: process.env.CLOUDFLARE_DATABASE_ID ?? "ae07e1bc-9646-4481-bcf1-f737e6468860",
    token: process.env.CLOUDFLARE_D1_TOKEN!,
  },
});
