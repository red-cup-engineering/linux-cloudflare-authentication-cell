import { access, mkdtemp, realpath, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

export const CLOUDFLARE_OAUTH_SCOPES = new Set([
  "account:read",
  "user:read",
  "workers:write",
  "workers_kv:write",
  "workers_routes:write",
  "workers_scripts:write",
  "workers_tail:read",
  "d1:write",
  "pages:write",
  "zone:read",
  "ssl_certs:write",
  "ai:write",
  "ai-search:write",
  "ai-search:run",
  "websearch.run",
  "agent-memory:write",
  "queues:write",
  "pipelines:write",
  "secrets_store:write",
  "artifacts:write",
  "flagship:write",
  "containers:write",
  "cloudchamber:write",
  "connectivity:admin",
  "email_routing:write",
  "email_sending:write",
  "browser:write",
  "challenge-widgets.write"
]);

const SECRET_ENVIRONMENT_KEYS = [
  "CLOUDFLARE_API_TOKEN",
  "CLOUDFLARE_API_KEY",
  "CLOUDFLARE_EMAIL",
  "CF_API_TOKEN",
  "CF_API_KEY",
  "CF_EMAIL"
];

const CELL_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function assertText(value, name) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value.trim();
}

export function validateAuthenticationRequest(request) {
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new TypeError("request must be an object");
  }
  const profile = assertText(request.profile, "profile");
  if (!/^[a-z][a-z0-9-]{1,62}$/.test(profile)) {
    throw new TypeError("profile must be 2-63 lowercase letters, digits, or hyphens and start with a letter");
  }
  const expectedAccountId = assertText(request.expectedAccountId, "expectedAccountId");
  if (!/^[a-f0-9]{32}$/i.test(expectedAccountId)) {
    throw new TypeError("expectedAccountId must be a 32-character Cloudflare account id");
  }
  if (!Array.isArray(request.scopes) || request.scopes.length === 0) {
    throw new TypeError("scopes must be a non-empty array; implicit default scopes are refused");
  }
  const scopes = [...new Set(request.scopes.map((scope) => assertText(scope, "scope")))].sort();
  for (const scope of scopes) {
    if (!CLOUDFLARE_OAUTH_SCOPES.has(scope)) {
      throw new TypeError(`unsupported Cloudflare OAuth scope: ${scope}`);
    }
  }
  const settlementDirectory = assertText(request.settlementDirectory, "settlementDirectory");
  const browser = request.browser !== false;
  const callbackHost = request.callbackHost ?? "localhost";
  if (callbackHost !== "localhost" && callbackHost !== "127.0.0.1" && callbackHost !== "::1") {
    throw new TypeError("callbackHost must remain on the Linux settlement loopback");
  }
  const callbackPort = request.callbackPort ?? 8976;
  if (!Number.isInteger(callbackPort) || callbackPort < 1024 || callbackPort > 65535) {
    throw new TypeError("callbackPort must be an unprivileged TCP port");
  }
  return { profile, expectedAccountId: expectedAccountId.toLowerCase(), scopes, settlementDirectory, browser, callbackHost, callbackPort };
}

function safeEnvironment(environment, compatibilityDirectory) {
  const safe = { ...environment };
  for (const key of SECRET_ENVIRONMENT_KEYS) delete safe[key];
  safe.CLOUDFLARE_AUTH_USE_KEYRING = "true";
  safe.PATH = `${compatibilityDirectory}:${environment.PATH ?? "/usr/local/bin:/usr/bin:/bin"}`;
  return safe;
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, options);
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status, signal) => {
      if (status !== 0) {
        reject(new Error(`${command} ${args[0] ?? ""} failed (${signal ?? status}): ${stderr.trim() || "no diagnostic"}`));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function extractAccounts(value, results = []) {
  if (Array.isArray(value)) {
    for (const item of value) extractAccounts(item, results);
  } else if (value && typeof value === "object") {
    if (typeof value.id === "string" && /^[a-f0-9]{32}$/i.test(value.id)) {
      results.push({ id: value.id.toLowerCase() });
    }
    for (const child of Object.values(value)) extractAccounts(child, results);
  }
  return results;
}

export async function authenticateLinuxColonyWithCloudflare(request, options = {}) {
  const input = validateAuthenticationRequest(request);
  const target = await realpath(input.settlementDirectory);
  await access(target, constants.R_OK | constants.X_OK);

  const wrangler = options.wranglerPath ?? join(CELL_ROOT, "node_modules", ".bin", "wrangler");
  const compatibilityDirectory = options.compatibilityDirectory ?? join(CELL_ROOT, "libexec");
  const execute = options.execute ?? run;
  const environment = safeEnvironment(options.environment ?? process.env, compatibilityDirectory);
  const verificationDirectory = await mkdtemp(join(tmpdir(), "cloudflare-profile-verification-"));

  const verifyProfile = async () => {
    await execute(wrangler, [
      "auth", "activate", input.profile, verificationDirectory
    ], { cwd: verificationDirectory, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    const verification = await execute(wrangler, [
      "whoami", "--json", "--account", input.expectedAccountId
    ], { cwd: verificationDirectory, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    let identity;
    try {
      identity = JSON.parse(verification.stdout);
    } catch {
      throw new Error("Wrangler returned a non-JSON identity response");
    }
    const candidate = extractAccounts(identity).find((item) => item.id === input.expectedAccountId);
    if (!candidate) {
      throw new Error(`authorized identity is not a member of expected Cloudflare account ${input.expectedAccountId}`);
    }
    return candidate;
  };

  let account;
  try {
    try {
      account = await verifyProfile();
    } catch {
      await execute(wrangler, [
        "auth", "create", input.profile,
        "--scopes", ...input.scopes,
        "--callback-host", input.callbackHost,
        "--callback-port", String(input.callbackPort),
        input.browser ? "--browser" : "--no-browser"
      ], { cwd: target, env: environment, stdio: "inherit" });
      account = await verifyProfile();
    }

    await execute(wrangler, [
      "auth", "activate", input.profile, target
    ], { cwd: target, env: environment, stdio: ["ignore", "pipe", "pipe"] });
  } finally {
    await rm(verificationDirectory, { recursive: true, force: true });
  }

  return {
    type: "LinuxCloudflareAuthenticationReceipt",
    profile: input.profile,
    account: { id: account.id },
    scopes: input.scopes,
    settlementDirectory: target,
    credentialCustody: "linux-secret-service",
    credentialReturned: false,
    verified: true
  };
}
