module.exports = {
  apps: [
    {
      name: "nota-entitlements",
      cwd: "/home/administrator/.openclaw/workspace/projects/nota-server",
      script: "dist/index.js",
      env: {
        NODE_ENV: "production",
        PORT: "3111",
        HOST: "127.0.0.1",
        TEST_MODE: "false",
        // Trial grant lives in untracked .env only (single beta account) — never commit the account id here.
        FIREBASE_PROJECT_ID: "nota-6d145",
      },
    },
  ],
};
