#!/usr/bin/env node
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const PROFILE = "org.red-cup-engineering.windows-current-user-dpapi-secret-tool.v1";
const POWERSHELL = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe";
const POWERSHELL_DPAPI = "$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Security;$r=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:RED_CUP_DPAPI_REQUEST))|ConvertFrom-Json);$p=[Convert]::FromBase64String([string]$r.payload);$e=[Text.Encoding]::UTF8.GetBytes([string]$r.entropy);if([string]$r.mode -eq 'protect'){$o=[Security.Cryptography.ProtectedData]::Protect($p,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)}elseif([string]$r.mode -eq 'unprotect'){$o=[Security.Cryptography.ProtectedData]::Unprotect($p,$e,[Security.Cryptography.DataProtectionScope]::CurrentUser)}else{throw 'inadmissible DPAPI operation'};[Console]::Out.Write([Convert]::ToBase64String($o))";

class DpapiSecretToolRefusal extends Error {
  constructor(code) { super(code); this.name = "DpapiSecretToolRefusal"; this.code = code; }
}

function parseAttributes(args) {
  const values = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index].startsWith("--label=")) continue;
    if (args[index] === "--label" || args[index] === "--collection") { index += 1; continue; }
    if (args[index].startsWith("--collection=")) continue;
    values.push(args[index]);
  }
  if (values.length === 0 || values.length % 2 !== 0) throw new DpapiSecretToolRefusal("SECRET_ATTRIBUTES_INVALID");
  const attributes = Object.fromEntries(Array.from({ length: values.length / 2 }, (_, index) => [values[index * 2], values[index * 2 + 1]]));
  if (attributes.service !== "wrangler" || typeof attributes.account !== "string" || attributes.account === "") {
    throw new DpapiSecretToolRefusal("SECRET_ATTRIBUTES_OUT_OF_SCOPE");
  }
  return Object.freeze({ service: attributes.service, account: attributes.account });
}

function coordinate(attributes) {
  return `${PROFILE}|service=${attributes.service}|account=${attributes.account}`;
}

function encodedPath(root, attributes) {
  return join(root, `${createHash("sha256").update(coordinate(attributes)).digest("hex")}.dpapi`);
}

async function runPowerShell(mode, payload, entropy, options = {}) {
  const powershell = options.powershellPath ?? POWERSHELL;
  const request = Buffer.from(JSON.stringify({ mode, payload: Buffer.from(payload).toString("base64"), entropy }), "utf8").toString("base64");
  const temporary = await mkdtemp(join("/dev/shm", "red-cup-dpapi-"));
  const responsePath = join(temporary, "response");
  const response = await open(responsePath, "w", 0o600);
  const encodedCommand = Buffer.from(POWERSHELL_DPAPI, "utf16le").toString("base64");
  try {
    await new Promise((resolvePromise, reject) => {
      const child = spawn("/bin/bash", ["-lc", `exec ${powershell} -NoProfile -NonInteractive -EncodedCommand ${encodedCommand}`], {
      stdio: ["ignore", response.fd, "ignore"], detached: process.platform !== "win32",
      env: {
        ...process.env,
        RED_CUP_DPAPI_REQUEST: request,
        WSLENV: [...String(process.env.WSLENV ?? "").split(":").filter(Boolean), "RED_CUP_DPAPI_REQUEST"].join(":"),
      },
    });
      let settled = false;
      const finish = (action) => { if (settled) return; settled = true; action(); };
      child.on("error", () => finish(() => reject(new DpapiSecretToolRefusal("DPAPI_PROCESS_UNAVAILABLE"))));
      child.on("close", (status) => finish(() => status === 0 ? resolvePromise() : reject(new DpapiSecretToolRefusal("DPAPI_OPERATION_REFUSED"))));
    });
    await response.close();
    const stdout = (await readFile(responsePath, "utf8")).trim();
    if (stdout.length > 2_000_000) throw new DpapiSecretToolRefusal("DPAPI_RESPONSE_TOO_LARGE");
    if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(stdout)) throw new DpapiSecretToolRefusal("DPAPI_OPERATION_REFUSED");
    return Buffer.from(stdout, "base64");
  } finally {
    await response.close().catch(() => {});
    await rm(temporary, { recursive: true, force: true });
  }
}

export function createWindowsCurrentUserDpapiSecretTool(options = {}) {
  const root = options.root ?? join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), ".wrangler", "dpapi");
  const protect = options.protect ?? ((value, entropy) => runPowerShell("protect", value, entropy, options));
  const unprotect = options.unprotect ?? ((value, entropy) => runPowerShell("unprotect", value, entropy, options));
  return Object.freeze({
    async store(attributes, secret) {
      const path = encodedPath(root, attributes), temporary = join(dirname(path), `.${process.pid}.${Date.now()}.dpapi`);
      const ciphertext = await protect(Buffer.from(secret), coordinate(attributes));
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(temporary, ciphertext, { mode: 0o600 });
      await chmod(temporary, 0o600);
      await rename(temporary, path);
    },
    async lookup(attributes) {
      let ciphertext;
      try { ciphertext = await readFile(encodedPath(root, attributes)); }
      catch (error) { if (error?.code === "ENOENT") return null; throw new DpapiSecretToolRefusal("DPAPI_CIPHERTEXT_UNREADABLE"); }
      return unprotect(ciphertext, coordinate(attributes));
    },
    async clear(attributes) { await rm(encodedPath(root, attributes), { force: true }); },
  });
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function main(args) {
  if (args.length === 1 && args[0] === "--version") { process.stdout.write("secret-tool (Windows CurrentUser DPAPI)\n"); return 0; }
  const [operation, ...attributeArgs] = args;
  if (!["store", "lookup", "clear"].includes(operation)) throw new DpapiSecretToolRefusal("SECRET_OPERATION_UNSUPPORTED");
  const attributes = parseAttributes(attributeArgs);
  const tool = createWindowsCurrentUserDpapiSecretTool();
  if (operation === "store") { await tool.store(attributes, await readStdin()); return 0; }
  if (operation === "lookup") {
    const value = await tool.lookup(attributes);
    if (value === null) return 1;
    process.stdout.write(value);
    if (value.at(-1) !== 10) process.stdout.write("\n");
    return 0;
  }
  await tool.clear(attributes);
  return 0;
}

if (resolve(process.argv[1] ?? "") === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((status) => { process.exitCode = status; }).catch((error) => {
    process.stderr.write(`${error?.code ?? "DPAPI_SECRET_TOOL_REFUSED"}\n`);
    process.exitCode = 70;
  });
}
