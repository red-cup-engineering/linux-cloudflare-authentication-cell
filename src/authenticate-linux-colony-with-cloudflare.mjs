import { access, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createAuthorityCustodyActuator } from "@red-cup-engineering/authority-custody-actuator";
import { semanticId } from "@red-cup-engineering/typed-resource-catalog";
import {
  authorizeCloudflareWithPkce
} from "./cloudflare-oauth-pkce.mjs";
import { createWranglerKeyringAuthoritySubstrate } from "./wrangler-keyring-authority-substrate.mjs";
import { projectAuthenticationReceipt } from "./project-authentication-receipt.mjs";

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
  "dns:write",
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
const DNS_MAPPING = Object.freeze({ zone: "561.group", type: "CNAME", name: "gui.561.group", content: "ghs.googlehosted.com", proxied: false, ttl: 1 });

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
  if (request.browser === false) {
    throw new TypeError("browser must be true; this cell transfers the one-time authorization URL directly and refuses copy/paste authentication");
  }
  const browser = true;
  const callbackHost = request.callbackHost ?? "localhost";
  if (callbackHost !== "localhost" && callbackHost !== "127.0.0.1") {
    throw new TypeError("callbackHost must be an IPv4-safe local spelling of the Cloudflare public client's registered localhost callback host");
  }
  const callbackPort = request.callbackPort ?? 8976;
  if (callbackPort !== 8976) {
    throw new TypeError("callbackPort must equal the Cloudflare public client's registered port 8976");
  }
  return { profile, expectedAccountId: expectedAccountId.toLowerCase(), scopes, settlementDirectory, browser, callbackHost, callbackPort };
}

function safeEnvironment(environment, compatibilityDirectory) {
  const safe = { ...environment };
  for (const key of SECRET_ENVIRONMENT_KEYS) delete safe[key];
  safe.CLOUDFLARE_AUTH_USE_KEYRING = "true";
  safe.WRANGLER_LOG_PATH ??= join(tmpdir(), "linux-cloudflare-authentication-cell-wrangler.log");
  safe.PATH = `${compatibilityDirectory}:${environment.PATH ?? "/usr/local/bin:/usr/bin:/bin"}`;
  return safe;
}

function run(command, args, options) {
  return new Promise((resolve, reject) => {
    const { sensitiveArgs = false, ...spawnOptions } = options;
    const commandLabel = sensitiveArgs ? command : `${command} ${args[0] ?? ""}`;
    const child = spawn(command, args, spawnOptions);
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk; });
    child.stderr?.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => {
      reject(error);
    });
    child.on("close", (status, signal) => {
      if (status !== 0) {
        const diagnostic = sensitiveArgs ? "target withheld" : stderr.trim() || stdout.trim() || "no diagnostic";
        const error = new Error(`${commandLabel} failed (${signal ?? status}): ${diagnostic}`);
        error.stdout = stdout;
        error.stderr = stderr;
        error.status = status;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

function openWslBrowser(url) {
  if (process.platform !== "linux" || !process.env.WSL_INTEROP) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "BROWSER_OPEN_UNAVAILABLE",
      "automatic authorization requires WSL browser interop on this settlement"
    );
  }
  return run("/usr/bin/wslview", [url], {
    stdio: ["ignore", "pipe", "pipe"],
    sensitiveArgs: true
  });
}

async function preflightWslBrowserCallback({ url, registeredRedirectUri }) {
  if (process.platform !== "linux" || !process.env.WSL_INTEROP
      || registeredRedirectUri !== "http://localhost:8976/oauth/callback"
      || url !== "http://localhost:8976/__cloudflare_auth_callback_ipv4_probe") {
    throw new LinuxCloudflareAuthenticationRefusal(
      "CALLBACK_PREFLIGHT_UNAVAILABLE",
      "the exact Windows-to-WSL callback preflight is unavailable"
    );
  }
  const result = await run("/mnt/c/windows/System32/WindowsPowerShell/v1.0/powershell.exe", [
    "-NoProfile", "-NonInteractive", "-Command",
    "(Invoke-WebRequest -UseBasicParsing http://localhost:8976/__cloudflare_auth_callback_ipv4_probe).StatusCode"
  ], { stdio: ["ignore", "pipe", "pipe"] });
  if (result.stdout.trim() !== "204") {
    throw new LinuxCloudflareAuthenticationRefusal(
      "CALLBACK_PREFLIGHT_FAILED",
      "Windows loopback did not reach the IPv4 WSL OAuth callback listener"
    );
  }
}

function executeObserved(execute, command, args, options) {
  return execute(command, args, options);
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

function verifyGrantedScopes(identity, requested) {
  if (!Array.isArray(identity?.tokenPermissions)) {
    throw new Error("Wrangler identity response does not disclose granted OAuth permissions");
  }
  const granted = [...new Set(identity.tokenPermissions)].sort();
  const expected = [...new Set([...requested, "offline_access"])].sort();
  if (JSON.stringify(granted) !== JSON.stringify(expected)) {
    throw new Error(`granted OAuth permissions differ from the exact request (expected ${expected.join(",")}; received ${granted.join(",")})`);
  }
}

export class LinuxCloudflareAuthenticationRefusal extends Error {
  constructor(code, message, evidence = {}) {
    super(message);
    this.name = "LinuxCloudflareAuthenticationRefusal";
    this.code = code;
    this.evidence = Object.freeze({ ...evidence });
  }

  toJSON() {
    return {
      type: "LinuxCloudflareAuthenticationRefusal",
      code: this.code,
      message: this.message,
      evidence: this.evidence,
      credentialReturned: false,
      verified: false
    };
  }
}

function cloudRunDnsInput(input) {
  const authentication = validateAuthenticationRequest(input?.authentication);
  const mapping = input?.mapping;
  if (!authentication.scopes.includes("dns:write") || !mapping || mapping.zone !== DNS_MAPPING.zone
      || mapping.type !== DNS_MAPPING.type || mapping.name !== DNS_MAPPING.name || mapping.content !== DNS_MAPPING.content
      || mapping.proxied !== DNS_MAPPING.proxied || mapping.ttl !== DNS_MAPPING.ttl) {
    throw new TypeError("reconciliation requires the exact dns:write gui.561.group Cloud Run CNAME declaration");
  }
  return { authentication, mapping: DNS_MAPPING };
}

async function cloudflareRequest(fetchImpl, token, path, init = {}) {
  const response = await fetchImpl(`https://api.cloudflare.com/client/v4${path}`, { ...init, headers: { authorization: `Bearer ${token}`, ...(init.headers ?? {}) } });
  const body = await response.json();
  if (!response.ok || body.success !== true) throw new LinuxCloudflareAuthenticationRefusal("DNS_API_REFUSED", `Cloudflare DNS request refused: ${JSON.stringify(body.errors ?? [])}`);
  return body.result;
}

/** Reconcile exactly one declared DNS-only Cloud Run CNAME without Wrangler or Worker deployment. */
export async function reconcileCloudRunDomainMappingDns(input, options = {}) {
  const { authentication, mapping } = cloudRunDnsInput(input);
  const inspection = await (options.inspect ?? inspectLinuxCloudflareAuthentication)(authentication, options);
  const credential = options.profileCredential
    ? await options.profileCredential(authentication.profile)
    : await createWranglerKeyringAuthoritySubstrate({
      secretToolPath: options.compatibilityDirectory ? join(options.compatibilityDirectory, "secret-tool") : join(CELL_ROOT, "libexec", "secret-tool"),
      configDirectory: options.configDirectory,
      secretToolExecute: options.secretToolExecute,
    }).readProfile(authentication.profile);
  const token = credential?.oauthToken;
  if (typeof token !== "string" || token.length === 0) throw new LinuxCloudflareAuthenticationRefusal("PROFILE_TOKEN_UNAVAILABLE", "named profile has no OAuth token");
  const fetchImpl = options.fetch ?? fetch;
  const zones = await cloudflareRequest(fetchImpl, token, `/zones?name=${encodeURIComponent(mapping.zone)}`);
  if (!Array.isArray(zones) || zones.length !== 1 || zones[0]?.name !== mapping.zone) throw new LinuxCloudflareAuthenticationRefusal("ZONE_AMBIGUOUS", "Cloudflare zone resolution is not exact");
  const zoneId = zones[0].id, listPath = `/zones/${zoneId}/dns_records?type=CNAME&name=${encodeURIComponent(mapping.name)}`;
  const records = await cloudflareRequest(fetchImpl, token, listPath);
  const matches = Array.isArray(records) ? records.filter((record) => record.type === mapping.type && record.name === mapping.name) : [];
  if (matches.length > 1) throw new LinuxCloudflareAuthenticationRefusal("DNS_DUPLICATE", "duplicate gui.561.group CNAME records refuse ambiguous mutation");
  const same = (record) => record.content === mapping.content && record.proxied === mapping.proxied && record.ttl === mapping.ttl;
  if (matches.length === 1 && same(matches[0])) return Object.freeze({ type: "CloudflareDnsReconciliationReceipt", disposition: "unchanged", zoneId, recordId: matches[0].id, mapping, inspection, credentialReturned: false });
  const method = matches.length === 1 ? "PUT" : "POST", path = matches.length === 1 ? `/zones/${zoneId}/dns_records/${matches[0].id}` : `/zones/${zoneId}/dns_records`;
  const result = await cloudflareRequest(fetchImpl, token, path, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(mapping) });
  return Object.freeze({ type: "CloudflareDnsReconciliationReceipt", disposition: matches.length === 1 ? "updated" : "created", zoneId, recordId: result.id, mapping, inspection, credentialReturned: false });
}

/**
 * Bind and mechanically verify an existing named profile without creating,
 * printing, or accepting an ambient credential.
 */
export async function inspectLinuxCloudflareAuthentication(request, options = {}) {
  const input = validateAuthenticationRequest(request);
  const target = await realpath(input.settlementDirectory);
  await access(target, constants.R_OK | constants.X_OK);

  const wrangler = options.wranglerPath ?? join(CELL_ROOT, "node_modules", ".bin", "wrangler");
  const compatibilityDirectory = options.compatibilityDirectory ?? join(CELL_ROOT, "libexec");
  const execute = options.execute ?? run;
  const environment = safeEnvironment(options.environment ?? process.env, compatibilityDirectory);

  try {
    await executeObserved(execute, join(compatibilityDirectory, "secret-tool"), ["--version"], {
      cwd: target, env: environment, stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "SECRET_TOOL_UNAVAILABLE",
      "libsecret-tools or its Wrangler-compatible probe is unavailable",
      { cause: error instanceof Error ? error.message : String(error) }
    );
  }

  const bindingsPath = options.directoryBindingsPath ?? join(
    options.environment?.XDG_CONFIG_HOME ?? process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"),
    ".wrangler", "profiles", "directory-bindings.json"
  );
  let bindings;
  try {
    bindings = JSON.parse(await readFile(bindingsPath, "utf8"));
  } catch (error) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "PROFILE_NOT_BOUND",
      `no readable Wrangler directory binding exists for ${target}`,
      { profile: input.profile, settlementDirectory: target, bindingsPath }
    );
  }
  if (bindings[target] !== input.profile) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "PROFILE_NOT_BOUND",
      `named Wrangler profile ${input.profile} exists but is not bound to ${target}`,
      { profile: input.profile, settlementDirectory: target, boundProfile: bindings[target] ?? null }
    );
  }

  let verification;
  try {
    verification = await executeObserved(execute, wrangler, ["whoami", "--json", "--account", input.expectedAccountId], {
      cwd: target, env: environment, stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    let identity;
    try {
      identity = JSON.parse(error?.stdout ?? "");
    } catch {
      // Preserve the Wrangler diagnostic below when the failure was not JSON.
    }
    throw new LinuxCloudflareAuthenticationRefusal(
      "AUTHORIZATION_UNAVAILABLE",
      identity?.loggedIn === false
        ? `named Wrangler profile ${input.profile} exists and is bound, but is not logged in`
        : `named Wrangler profile ${input.profile} exists and is bound, but its Cloudflare authorization is unavailable`,
      { profile: input.profile, cause: error instanceof Error ? error.message : String(error) }
    );
  }

  let identity;
  try {
    identity = JSON.parse(verification.stdout);
  } catch {
    throw new LinuxCloudflareAuthenticationRefusal(
      "IDENTITY_MALFORMED",
      "Wrangler returned a non-JSON identity response",
      { profile: input.profile }
    );
  }
  if (identity?.loggedIn === false) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "AUTHORIZATION_UNAVAILABLE",
      `named Wrangler profile ${input.profile} exists but is not logged in`,
      { profile: input.profile }
    );
  }
  const account = extractAccounts(identity).find((item) => item.id === input.expectedAccountId);
  if (!account) {
    throw new LinuxCloudflareAuthenticationRefusal(
      "ACCOUNT_MISMATCH",
      `authorized identity is not a member of expected Cloudflare account ${input.expectedAccountId}`,
      { profile: input.profile, expectedAccountId: input.expectedAccountId }
    );
  }

  return {
    type: "LinuxCloudflareAuthenticationInspection",
    profile: input.profile,
    account,
    settlementDirectory: target,
    secretToolProbe: "compatible",
    credentialCustody: "linux-secret-service",
    credentialReturned: false,
    verified: true
  };
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
  const progress = typeof options.onProgress === "function" ? options.onProgress : () => {};

  const verifyProfile = async () => {
    await executeObserved(execute, wrangler, [
      "auth", "activate", input.profile, verificationDirectory
    ], { cwd: verificationDirectory, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    const verification = await executeObserved(execute, wrangler, [
      "whoami", "--json", "--account", input.expectedAccountId
    ], { cwd: verificationDirectory, env: environment, stdio: ["ignore", "pipe", "pipe"] });
    let identity;
    try {
      identity = JSON.parse(verification.stdout);
    } catch {
      throw new Error("Wrangler returned a non-JSON identity response");
    }
    verifyGrantedScopes(identity, input.scopes);
    const candidate = extractAccounts(identity).find((item) => item.id === input.expectedAccountId);
    if (!candidate) {
      throw new Error(`authorized identity is not a member of expected Cloudflare account ${input.expectedAccountId}`);
    }
    return candidate;
  };

  let account;
  let authority = null;
  try {
    progress({ type: "LinuxCloudflareAuthenticationProgress", phase: "profile-probe", message: `Checking named Cloudflare profile ${input.profile} until it returns, is cancelled, or reports a transport failure.` });
    try {
      account = await verifyProfile();
      progress({ type: "LinuxCloudflareAuthenticationProgress", phase: "profile-reused", message: `Named Cloudflare profile ${input.profile} passed exact account and scope verification.` });
    } catch (probeError) {
      progress({
        type: "LinuxCloudflareAuthenticationProgress",
        phase: "reauthorization-required",
        message: `Named Cloudflare profile ${input.profile} is absent or unusable; starting visible interactive reauthorization now.`,
        reason: probeError?.code ?? "PROFILE_UNUSABLE"
      });
      const authorize = options.authorize ?? authorizeCloudflareWithPkce;
      const custody = options.authorityCustody ?? createAuthorityCustodyActuator({
        substrate: options.authoritySubstrate ?? createWranglerKeyringAuthoritySubstrate({
          configDirectory: options.wranglerConfigDirectory,
          secretToolPath: join(compatibilityDirectory, "secret-tool")
        })
      });
      const authorization = await authorize(input, {
        openBrowser: options.openBrowser ?? openWslBrowser,
        preflightCallback: options.preflightCallback ?? preflightWslBrowserCallback,
        fetchImpl: options.fetchImpl,
        endpoints: options.oauthEndpoints,
        tokenAttempts: options.tokenAttempts,
        storeCredential: options.storeCredential ?? ((credential) => custody.store({
          provider: "cloudflare",
          subject: credential.profile,
          attributes: {
            accountId: input.expectedAccountId,
            scopes: input.scopes
          },
          secret: { ...credential }
        }))
      });
      authority = authorization?.authority ?? null;
      progress({ type: "LinuxCloudflareAuthenticationProgress", phase: "profile-verification", message: `Interactive authorization returned; verifying exact account and scopes for ${input.profile}.` });
      try {
        account = await verifyProfile();
      } catch (error) {
        throw new LinuxCloudflareAuthenticationRefusal(
          "PROFILE_VERIFICATION_FAILED",
          `newly authorized profile failed exact verification: ${error instanceof Error ? error.message : String(error)}`,
          { profile: input.profile }
        );
      }
    }

    progress({ type: "LinuxCloudflareAuthenticationProgress", phase: "profile-activation", message: `Binding verified profile ${input.profile} to the requested settlement.` });
    await executeObserved(execute, wrangler, [
      "auth", "activate", input.profile, target
    ], { cwd: target, env: environment, stdio: ["ignore", "pipe", "pipe"] });
  } finally {
    try {
      await executeObserved(execute, wrangler, ["auth", "deactivate", verificationDirectory], {
        cwd: target, env: environment, stdio: ["ignore", "pipe", "pipe"]
      });
    } catch {
      // The disposable directory is still removed; Wrangler may already have
      // removed the binding as part of a failed activation.
    }
    await rm(verificationDirectory, { recursive: true, force: true });
  }

  const body = Object.freeze({
    type: "LinuxCloudflareAuthenticationReceipt",
    profile: input.profile,
    account: { id: account.id },
    scopes: input.scopes,
    settlementDirectory: target,
    credentialCustody: "linux-secret-service",
    authority,
    credentialReturned: false,
    verified: true
  });
  const receipt = Object.freeze({ ...body, id: semanticId(body) });
  return Object.freeze({ ...receipt, ...projectAuthenticationReceipt(receipt) });
}
