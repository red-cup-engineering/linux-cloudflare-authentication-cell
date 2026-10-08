import test from "node:test";
import assert from "node:assert/strict";
import { access, mkdir, mkdtemp, readFile, readlink, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authenticateLinuxColonyWithCloudflare,
  inspectLinuxCloudflareAuthentication,
  LinuxCloudflareAuthenticationRefusal
} from "../src/authenticate-linux-colony-with-cloudflare.mjs";

const accountId = "0123456789abcdef0123456789abcdef";
const identity = { loggedIn: true, accounts: [{ id: accountId }], tokenPermissions: ["account:read", "offline_access"] };
const output = (value) => ({ stdout: JSON.stringify(value), stderr: "" });

async function fixture(t, { existing = true } = {}) {
  const root = await mkdtemp(join(tmpdir(), "cloudflare-auth-recovery-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const configDirectory = join(root, "xdg", ".wrangler");
  await mkdir(join(configDirectory, "config"), { recursive: true });
  const profilePath = join(configDirectory, "config", "test-profile.enc");
  const originalBytes = "synthetic encrypted profile fixture; not a credential\n";
  if (existing) await writeFile(profilePath, originalBytes);
  const calls = [], progress = [];
  let authorizations = 0;
  const request = { profile: "test-profile", expectedAccountId: accountId, scopes: ["account:read"], settlementDirectory: root };
  const options = {
    wranglerConfigDirectory: configDirectory,
    environment: { HOME: root, XDG_CONFIG_HOME: join(root, "xdg"), PATH: "/usr/bin" },
    onProgress: (event) => progress.push(event),
    authorize: async () => { authorizations += 1; },
    execute: async (_command, args) => { calls.push(args); return args[0] === "whoami" ? output(identity) : { stdout: "", stderr: "" }; }
  };
  return { root, configDirectory, profilePath, originalBytes, calls, progress, request, options, authorizations: () => authorizations };
}

const failures = [
  ["transport", Object.assign(new Error("transport diagnostic must not leak"), { code: "ECONNRESET" }), "PROFILE_TRANSPORT_FAILED"],
  ["permission", Object.assign(new Error("permission diagnostic must not leak"), { code: "EACCES" }), "PROFILE_CUSTODY_UNREADABLE"],
  ["decryption", Object.assign(new Error("decryption diagnostic must not leak"), { code: "ERR_OSSL_BAD_DECRYPT" }), "PROFILE_CUSTODY_UNREADABLE"],
  ["missing executable", Object.assign(new Error("spawn failed"), { code: "ENOENT" }), "WRANGLER_UNAVAILABLE"],
  ["unclassified process failure", Object.assign(new Error("opaque diagnostic must not leak"), { status: 1 }), "PROFILE_PROBE_FAILED"],
  ["cancelled process", Object.assign(new Error("cancelled"), { signal: "SIGTERM", status: null }), "PROFILE_PROBE_CANCELLED"],
  ["unavailable grant or custody", Object.assign(new Error("not logged in"), { stdout: '{"loggedIn":false}', status: 1 }), "AUTHORIZATION_UNAVAILABLE"]
];

for (const [name, failure, code] of failures) {
  test(`existing ${name} refuses without authorization or profile replacement`, async (t) => {
    const f = await fixture(t);
    const execute = f.options.execute;
    f.options.execute = async (command, args) => {
      if (args[0] === "whoami") { f.calls.push(args); throw failure; }
      return execute(command, args);
    };
    await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), (error) => {
      assert.ok(error instanceof LinuxCloudflareAuthenticationRefusal);
      assert.equal(error.code, code);
      assert.equal(JSON.stringify(error.toJSON()).includes("must not leak"), false);
      return true;
    });
    assert.equal(f.authorizations(), 0);
    assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
    assert.equal(f.calls.some((args) => args[1] === "activate" && args[3] === f.root), false);
    assert.equal(f.progress.some(({ phase }) => phase === "reauthorization-required"), false);
    assert.ok(f.calls.some((args) => args[1] === "deactivate"));
    const temporaryDirectory = f.calls.find((args) => args[1] === "deactivate")[2];
    await assert.rejects(access(temporaryDirectory), { code: "ENOENT" });
  });
}

for (const [name, response, code] of [
  ["malformed JSON", { stdout: "not JSON", stderr: "" }, "IDENTITY_MALFORMED"],
  ["wrong account", output({ ...identity, accounts: [{ id: "f".repeat(32) }] }), "ACCOUNT_MISMATCH"],
  ["broader scopes", output({ ...identity, tokenPermissions: [...identity.tokenPermissions, "dns:write"] }), "SCOPE_MISMATCH"],
  ["narrower scopes", output({ ...identity, tokenPermissions: ["offline_access"] }), "SCOPE_MISMATCH"],
  ["undisclosed scopes", output({ ...identity, tokenPermissions: undefined }), "IDENTITY_MALFORMED"],
  ["invalid scope values", output({ ...identity, tokenPermissions: [{ token: "must not leak" }] }), "IDENTITY_MALFORMED"],
  ["incomplete identity", output({ accounts: [{ id: accountId }], tokenPermissions: identity.tokenPermissions }), "IDENTITY_MALFORMED"],
  ["logged out success output", output({ loggedIn: false }), "AUTHORIZATION_UNAVAILABLE"]
]) {
  test(`existing ${name} refuses without authorization or profile replacement`, async (t) => {
    const f = await fixture(t);
    const execute = f.options.execute;
    f.options.execute = (command, args) => args[0] === "whoami" ? Promise.resolve(response) : execute(command, args);
    await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), (error) => error instanceof LinuxCloudflareAuthenticationRefusal && error.code === code);
    assert.equal(f.authorizations(), 0);
    assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
    assert.equal(f.calls.some((args) => args[1] === "activate" && args[3] === f.root), false);
  });
}

test("exact existing profile is reused without authorization", async (t) => {
  const f = await fixture(t);
  const receipt = await authenticateLinuxColonyWithCloudflare(f.request, f.options);
  assert.equal(f.authorizations(), 0);
  assert.equal(receipt.verified, true);
  assert.deepEqual(receipt.scopes, ["account:read"]);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

test("final settlement activation refuses without leaking subprocess diagnostics", async (t) => {
  const f = await fixture(t);
  const execute = f.options.execute;
  const sensitive = "synthetic-sensitive-diagnostic-must-not-cross";
  f.options.execute = async (command, args) => {
    if (args[1] === "activate" && args[3] === f.root) {
      f.calls.push(args);
      throw Object.assign(new Error(`wrangler auth failed: ${sensitive}`), {
        stdout: sensitive,
        stderr: `https://example.invalid/oauth?code=${sensitive}`,
        status: 1
      });
    }
    return execute(command, args);
  };
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), (error) => {
    assert.ok(error instanceof LinuxCloudflareAuthenticationRefusal);
    assert.equal(error.code, "PROFILE_PROBE_FAILED");
    assert.deepEqual(error.evidence, { profile: "test-profile", stage: "target-activation", exitStatus: 1 });
    assert.equal(JSON.stringify(error.toJSON()).includes(sensitive), false);
    assert.equal(String(error).includes(sensitive), false);
    assert.equal(error.stdout, undefined);
    assert.equal(error.stderr, undefined);
    return true;
  });
  assert.equal(f.authorizations(), 0);
  assert.equal(JSON.stringify(f.progress).includes(sensitive), false);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
  const cleanup = f.calls.find((args) => args[1] === "deactivate");
  assert.ok(cleanup);
  await assert.rejects(access(cleanup[2]), { code: "ENOENT" });
});

test("confirmed absent profile authorizes once with the exact request then verifies", async (t) => {
  const f = await fixture(t, { existing: false });
  const authorize = f.options.authorize;
  f.options.authorize = async (input) => {
    assert.equal(input.profile, f.request.profile);
    assert.equal(input.expectedAccountId, accountId);
    assert.deepEqual(input.scopes, ["account:read"]);
    await authorize();
    await writeFile(f.profilePath, f.originalBytes);
  };
  const receipt = await authenticateLinuxColonyWithCloudflare(f.request, f.options);
  assert.equal(f.authorizations(), 1);
  assert.equal(receipt.verified, true);
  assert.ok(f.progress.some(({ reason }) => reason === "PROFILE_ABSENT"));
});

test("a plaintext named profile also prevents replacement", async (t) => {
  const f = await fixture(t);
  const plaintextPath = f.profilePath.replace(/\.enc$/u, ".toml");
  await rename(f.profilePath, plaintextPath);
  const receipt = await authenticateLinuxColonyWithCloudflare(f.request, f.options);
  assert.equal(receipt.verified, true);
  assert.equal(f.authorizations(), 0);
  assert.equal(await readFile(plaintextPath, "utf8"), f.originalBytes);
});

test("a dangling profile symlink is existing custody, not absence", async (t) => {
  const f = await fixture(t, { existing: false });
  await symlink("missing-target", f.profilePath);
  const execute = f.options.execute;
  f.options.execute = (command, args) => args[0] === "whoami" ? Promise.resolve(output({ loggedIn: false })) : execute(command, args);
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "AUTHORIZATION_UNAVAILABLE" });
  assert.equal(f.authorizations(), 0);
  assert.equal(await readlink(f.profilePath), "missing-target");
});

test("unreadable metadata refuses even when profile presence is unknown", async (t) => {
  const f = await fixture(t);
  f.options.profileMetadata = async () => { throw Object.assign(new Error("must not leak"), { code: "EACCES" }); };
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), (error) => error.code === "PROFILE_CUSTODY_UNREADABLE" && error.evidence.stage === "profile-metadata");
  assert.equal(f.authorizations(), 0);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

test("a custody override cannot make an existing Wrangler profile look absent", async (t) => {
  const f = await fixture(t);
  f.options.wranglerConfigDirectory = join(f.root, "unrelated-directory");
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "PROFILE_CONFIG_MISMATCH" });
  assert.equal(f.authorizations(), 0);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

for (const kind of ["legacy", "xdg"]) {
  test(`metadata follows pinned Wrangler ${kind} config resolution`, async (t) => {
    const f = await fixture(t);
    const configDirectory = kind === "legacy" ? join(f.root, ".wrangler") : join(f.root, "xdg", ".wrangler");
    await mkdir(join(configDirectory, "config"), { recursive: true });
    await rename(f.profilePath, join(configDirectory, "config", "test-profile.enc"));
    delete f.options.wranglerConfigDirectory;
    f.options.environment.XDG_CONFIG_HOME = join(f.root, "xdg");
    const receipt = await authenticateLinuxColonyWithCloudflare(f.request, f.options);
    assert.equal(receipt.verified, true);
    assert.equal(f.authorizations(), 0);
  });
}

test("a dangling legacy config directory is not permission to create a new profile", async (t) => {
  const f = await fixture(t, { existing: false });
  await symlink("missing-config", join(f.root, ".wrangler"));
  delete f.options.wranglerConfigDirectory;
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "PROFILE_CUSTODY_UNREADABLE" });
  assert.equal(f.authorizations(), 0);
});

for (const tool of ["wrangler", "secret-tool"]) {
  test(`absent profile still refuses when ${tool} preflight fails`, async (t) => {
    const f = await fixture(t, { existing: false });
    const execute = f.options.execute;
    f.options.execute = async (command, args) => {
      if (command.endsWith(`/${tool}`) && args[0] === "--version") throw Object.assign(new Error("must not leak"), { code: "ENOENT" });
      return execute(command, args);
    };
    await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: tool === "wrangler" ? "WRANGLER_UNAVAILABLE" : "SECRET_TOOL_UNAVAILABLE" });
    assert.equal(f.authorizations(), 0);
  });
}

test("an activation error claiming absence does not override existing metadata", async (t) => {
  const f = await fixture(t);
  f.options.execute = async (_command, args) => {
    if (args[1] === "activate") throw new Error('Profile "test-profile" does not exist.');
    return { stdout: "", stderr: "" };
  };
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "PROFILE_PROBE_FAILED" });
  assert.equal(f.authorizations(), 0);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

test("a profile appearing during tooling preflight is not replaced", async (t) => {
  const f = await fixture(t, { existing: false });
  const execute = f.options.execute;
  f.options.execute = async (command, args) => {
    if (command.endsWith("/secret-tool")) await writeFile(f.profilePath, f.originalBytes);
    return execute(command, args);
  };
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "PROFILE_CHANGED" });
  assert.equal(f.authorizations(), 0);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

test("a profile appearing during authorization is not overwritten by credential storage", async (t) => {
  const f = await fixture(t, { existing: false });
  let stores = 0;
  f.options.storeCredential = async () => { stores += 1; };
  f.options.authorize = async (_input, { storeCredential }) => {
    await writeFile(f.profilePath, f.originalBytes);
    await storeCredential({ profile: "test-profile" });
  };
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), { code: "PROFILE_CHANGED" });
  assert.equal(stores, 0);
  assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
});

test("new authorization is verified once and never retried for a wrong account", async (t) => {
  const f = await fixture(t, { existing: false });
  const execute = f.options.execute;
  f.options.execute = (command, args) => args[0] === "whoami" ? Promise.resolve(output({ ...identity, accounts: [] })) : execute(command, args);
  await assert.rejects(authenticateLinuxColonyWithCloudflare(f.request, f.options), (error) => error.code === "PROFILE_VERIFICATION_FAILED" && error.evidence.reason === "ACCOUNT_MISMATCH");
  assert.equal(f.authorizations(), 1);
  assert.equal(f.calls.some((args) => args[1] === "activate" && args[3] === f.root), false);
});

for (const [name, result, code] of [
  ["broader scopes", output({ ...identity, tokenPermissions: [...identity.tokenPermissions, "dns:write"] }), "SCOPE_MISMATCH"],
  ["transport failure", Object.assign(new Error("must not leak"), { code: "ECONNRESET", stdout: "private stdout", stderr: "private stderr" }), "PROFILE_TRANSPORT_FAILED"],
  ["custody failure with logged-out output", Object.assign(new Error("must not leak"), { code: "EACCES", stdout: '{"loggedIn":false}' }), "PROFILE_CUSTODY_UNREADABLE"]
]) {
  test(`inspection reports ${name} without authorization or mutation`, async (t) => {
    const f = await fixture(t);
    const bindingsPath = join(f.root, "bindings.json");
    const bindings = JSON.stringify({ [f.root]: "test-profile" });
    await writeFile(bindingsPath, bindings);
    f.options.directoryBindingsPath = bindingsPath;
    f.options.execute = async (_command, args) => {
      f.calls.push(args);
      if (args[0] === "whoami") {
        if (result instanceof Error) throw result;
        return result;
      }
      return { stdout: "compatible", stderr: "" };
    };
    await assert.rejects(inspectLinuxCloudflareAuthentication(f.request, f.options), (error) => {
      assert.equal(error.code, code);
      assert.doesNotMatch(JSON.stringify(error.toJSON()), /must not leak|private stdout|private stderr/u);
      return true;
    });
    assert.equal(f.authorizations(), 0);
    assert.equal(await readFile(bindingsPath, "utf8"), bindings);
    assert.equal(await readFile(f.profilePath, "utf8"), f.originalBytes);
    assert.equal(f.calls.some((args) => args[0] === "auth"), false);
  });
}
