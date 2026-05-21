import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: process.env.TH_BASE_URL ?? "https://localhost:5999",
    ignoreHTTPSErrors: true,
    permissions: ["clipboard-read", "clipboard-write"],
  },
  projects: [
    { name: "chromium", use: { browserName: "chromium" } },
  ],
});
