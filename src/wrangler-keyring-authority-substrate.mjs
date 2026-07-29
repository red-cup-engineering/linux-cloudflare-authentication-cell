import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import { CloudflareOAuthRefusal } from "./cloudflare-oauth-pkce.mjs";

function runSecretTool(secretToolPath, args, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(secretToolPath, args, { stdio: ["pipe", "pipe", "pipe"], detached: process.platform !== "win32" });
    let stdout = "";
    let settled = false;
    const finish = (action) => {
      if (settled) return;
      settled = true;
      action();
    };
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.resume();
    child.on("error", (error) => finish(() => reject(error)));
    child.on("close", (status) => finish(() => resolve({ status, stdout })));
    child.stdin.end(input);
  });
}

function serialize(secret) {
  const lines = [
    `oauth_token = ${JSON.stringify(secret.oauthToken)}`,
    `expiration_time = ${JSON.stringify(secret.expirationTime)}`,
  ];
  if (secret.refreshToken !== undefined) lines.push(`refresh_token = ${JSON.stringify(secret.refreshToken)}`);
  lines.push(`scopes = [${secret.scopes.map((scope) => JSON.stringify(scope)).join(", ")}]`, "");
  return lines.join("\n");
}

function deserialize(value) {
  const field = (name) => JSON.parse(new RegExp(`^${name} = (.+)$`, "mu").exec(value)?.[1] ?? "null");
  return { oauthToken: field("oauth_token"), expirationTime: field("expiration_time"), refreshToken: field("refresh_token") ?? undefined, scopes: field("scopes") };
}

export function createWranglerKeyringAuthoritySubstrate(options = {}) {
  const configDirectory = options.configDirectory ?? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), ".wrangler");
  const secretToolPath = options.secretToolPath ?? "secret-tool";
  const execute = options.secretToolExecute
    ? ((args, input) => options.secretToolExecute(args, input))
    : ((args, input) => runSecretTool(secretToolPath, args, input));
  const profiles = new Map();
  const attributes = (profile) => ["service", "wrangler", "account", profile];
  const paths = (profile) => ({ directory: join(configDirectory, "config"), encrypted: join(configDirectory, "config", `${profile}.enc`), plaintext: join(configDirectory, "config", `${profile}.toml`) });
  async function keyFor(profile, create) {
    const found = await execute(["lookup", ...attributes(profile)]);
    if (found.status === 0) {
      try {
        const envelope = JSON.parse(found.stdout.trim());
        const key = envelope.v === 1 ? Buffer.from(envelope.key, "base64") : undefined;
        if (key?.length === 32) return key;
      } catch {}
    }
    if (!create) return undefined;
    const key = randomBytes(32);
    const envelope = JSON.stringify({ v: 1, key: key.toString("base64"), created: new Date().toISOString() });
    const stored = await execute(["store", "--label=Cloudflare credentials key", ...attributes(profile)], envelope);
    if (stored.status !== 0) throw new CloudflareOAuthRefusal("SECRET_SERVICE_WRITE_FAILED", "Secret Service refused the Wrangler encryption key");
    return key;
  }
  return Object.freeze({
    async store({ reference, secret }) {
      const { profile } = secret;
      const key = await keyFor(profile, true);
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      const ciphertext = Buffer.concat([cipher.update(serialize(secret), "utf8"), cipher.final()]);
      const envelope = JSON.stringify({ v: 1, alg: "AES-256-GCM", iv: iv.toString("base64"), tag: cipher.getAuthTag().toString("base64"), ciphertext: ciphertext.toString("base64") }, null, "\t");
      const target = paths(profile);
      const temporary = join(target.directory, `.${profile}.${process.pid}.enc`);
      await mkdir(target.directory, { recursive: true });
      await writeFile(temporary, envelope, { mode: 0o600 });
      await chmod(temporary, 0o600);
      await rename(temporary, target.encrypted);
      await rm(target.plaintext, { force: true });
      profiles.set(reference, profile);
    },
    async retrieve(reference) {
      const profile = profiles.get(reference);
      if (!profile) return null;
      const key = await keyFor(profile, false);
      if (!key) return null;
      const envelope = JSON.parse(await readFile(paths(profile).encrypted, "utf8"));
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.iv, "base64"));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
      return { profile, ...deserialize(plaintext) };
    },
    async revoke(reference) {
      const profile = profiles.get(reference);
      if (!profile) return;
      await rm(paths(profile).encrypted, { force: true });
      await rm(paths(profile).plaintext, { force: true });
      await execute(["clear", ...attributes(profile)]);
      profiles.delete(reference);
    }
  });
}
