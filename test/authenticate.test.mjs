import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authenticateLinuxColonyWithCloudflare,
  inspectLinuxCloudflareAuthentication,
  LinuxCloudflareAuthenticationRefusal,
  validateAuthenticationRequest
} from "../src/authenticate-linux-colony-with-cloudflare.mjs";

const accountId = "0123456789abcdef0123456789abcdef";

async function testDirectory(t, existing = true) {
  const directory = await mkdtemp(join(tmpdir(), "cloudflare-auth-cell-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await mkdir(join(directory, ".wrangler", "config"), { recursive: true });
  if (existing) await writeFile(join(directory, ".wrangler", "config", "bare-cedar-fog.enc"), "synthetic profile fixture");
  return directory;
}

test("refuses implicit and unknown authority", () => {
  assert.throws(() => validateAuthenticationRequest({ profile: "union", expectedAccountId: accountId, scopes: [], settlementDirectory: "/" }), /non-empty/);
  assert.throws(() => validateAuthenticationRequest({ profile: "union", expectedAccountId: accountId, scopes: ["dns:edit"], settlementDirectory: "/" }), /unsupported/);
  assert.throws(() => validateAuthenticationRequest({ profile: "union", expectedAccountId: accountId, scopes: ["account:read"], settlementDirectory: "/", browser: false }), /directly/);
});

test("admits the exact private MUD deployment authority expressible by Wrangler OAuth", () => {
  const request = validateAuthenticationRequest({
    profile: "bare-cedar-fog-semantic-content-identity",
    expectedAccountId: accountId,
    scopes: [
      "workers_scripts:write",
      "connectivity:admin",
      "workers_routes:write",
      "dns:write",
      "zone:read",
      "user:read",
      "account:read"
    ],
    settlementDirectory: "/home/emsenn/info/lib/emsenn/services/561-group/sites/561.group",
    browser: true
  });
  assert.deepEqual(request.scopes, [
    "account:read",
    "connectivity:admin",
    "dns:write",
    "user:read",
    "workers_routes:write",
    "workers_scripts:write",
    "zone:read"
  ]);
});

test("authorizes, verifies, then activates without ambient credentials", async (t) => {
  const directory = await testDirectory(t, false);
  const expectedDirectory = await realpath(directory);
  const calls = [];
  const authorizations = [];
  const execute = async (command, args, options) => {
    calls.push({ command, args, options });
    if (args.includes("whoami")) return { stdout: JSON.stringify({ loggedIn: true, accounts: [{ id: accountId, name: "Union" }], tokenPermissions: ["offline_access", "workers_scripts:write", "account:read"] }), stderr: "" };
    return { stdout: "", stderr: "" };
  };
  const receipt = await authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["workers_scripts:write", "account:read"],
    settlementDirectory: directory,
    browser: true
  }, {
    wranglerConfigDirectory: join(directory, ".wrangler"),
    authorize: async (input) => {
      authorizations.push(input);
      return {
        authority: {
          profile: "org.red-cup-engineering.opaque-authority-reference.v1",
          type: "OpaqueAuthorityReference",
          reference: "urn:authority:test",
          content: `ni:///sha-256;${"A".repeat(43)}`,
          secretBytesReturned: false
        }
      };
    },
    execute,
    wranglerPath: "/cell/wrangler",
    compatibilityDirectory: "/cell/libexec",
    environment: {
      HOME: directory,
      PATH: "/usr/bin",
      CLOUDFLARE_API_TOKEN: "must-not-cross",
      CLOUDFLARE_API_KEY: "must-not-cross"
    }
  });

  assert.equal(calls.length, 6);
  assert.equal(authorizations.length, 1);
  assert.deepEqual(authorizations[0].scopes, ["account:read", "workers_scripts:write"]);
  assert.equal(calls[2].args[0], "auth");
  assert.equal(calls[2].args[1], "activate");
  assert.deepEqual(calls[3].args, ["whoami", "--json", "--account", accountId]);
  assert.deepEqual(calls[4].args, ["auth", "activate", "bare-cedar-fog", expectedDirectory]);
  assert.equal(calls[5].args[0], "auth");
  assert.equal(calls[5].args[1], "deactivate");
  assert.equal(calls[1].options.env.CLOUDFLARE_AUTH_USE_KEYRING, "true");
  assert.equal(calls[1].options.env.CLOUDFLARE_API_TOKEN, undefined);
  assert.equal(calls[1].options.env.CLOUDFLARE_API_KEY, undefined);
  assert.equal(receipt.credentialReturned, false);
  assert.equal(receipt.authority.reference, "urn:authority:test");
  assert.equal(receipt.authority.secretBytesReturned, false);
  assert.equal(receipt.activity.type, "Create");
  assert.equal(receipt.activity.to, "https://www.w3.org/ns/activitystreams#Public");
  assert.match(receipt.activity.id, /\/activities\/rmn-/u);
  assert.equal(receipt.rmn.mediaType, "application/rmn+cbor");
  assert.equal(JSON.stringify(receipt).includes("must-not-cross"), false);
});

test("an unavailable existing profile reports refusal without interactive authorization", async (t) => {
  const directory = await testDirectory(t);
  const progress = [];
  let authorized = false;
  await assert.rejects(authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, {
    wranglerConfigDirectory: join(directory, ".wrangler"), environment: { HOME: directory },
    authorize: async () => { authorized = true; },
    onProgress: (event) => progress.push(event),
    execute: async (_command, args) => {
      if (args[0] === "whoami") throw Object.assign(new Error("not logged in"), { stdout: '{"loggedIn":false}', status: 1 });
      return { stdout: "", stderr: "" };
    }
  }), (error) => error instanceof LinuxCloudflareAuthenticationRefusal && error.code === "AUTHORIZATION_UNAVAILABLE");
  assert.equal(authorized, false);
  assert.equal(progress.some(({ phase }) => phase === "reauthorization-required"), false);
});

test("does not activate an unexpected account", async (t) => {
  const directory = await testDirectory(t);
  let calls = 0;
  await assert.rejects(authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, {
    wranglerConfigDirectory: join(directory, ".wrangler"), environment: { HOME: directory },
    authorize: async () => { assert.fail("existing profile must not be replaced"); },
    execute: async (_command, args) => {
      calls += 1;
      if (args.includes("whoami")) return { stdout: JSON.stringify({ loggedIn: true, accounts: [{ id: "f".repeat(32) }], tokenPermissions: ["account:read", "offline_access"] }), stderr: "" };
      return { stdout: "", stderr: "" };
    }
  }), /not a member/);
  assert.equal(calls, 3);
});

test("does not reuse a profile carrying broader authority", async (t) => {
  const directory = await testDirectory(t);
  let calls = 0;
  await assert.rejects(authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory,
    browser: true
  }, {
    wranglerConfigDirectory: join(directory, ".wrangler"), environment: { HOME: directory },
    authorize: async () => { assert.fail("existing profile must not be replaced"); },
    execute: async (_command, args) => {
      calls += 1;
      if (args.includes("whoami")) {
        return { stdout: JSON.stringify({
          loggedIn: true,
          accounts: [{ id: accountId }],
          tokenPermissions: ["account:read", "offline_access", "workers:write"]
        }), stderr: "" };
      }
      return { stdout: "", stderr: "" };
    }
  }), /granted OAuth permissions differ/);
  assert.equal(calls, 3);
});

test("inspection distinguishes an unavailable named profile from a missing secret-tool", async (t) => {
  const directory = await testDirectory(t);
  const bindingsPath = join(directory, "bindings.json");
  await writeFile(bindingsPath, JSON.stringify({ [directory]: "bare-cedar-fog" }));
  const calls = [];
  await assert.rejects(inspectLinuxCloudflareAuthentication({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, {
    wranglerPath: "/cell/wrangler",
    compatibilityDirectory: "/cell/libexec",
    directoryBindingsPath: bindingsPath,
    execute: async (command, args, options) => {
      calls.push({ command, args, options });
      if (args.includes("whoami")) {
        const error = new Error("not logged in");
        error.stdout = '{"loggedIn":false}';
        throw error;
      }
      return { stdout: "secret-tool (libsecret-tools)", stderr: "" };
    }
  }), (error) => {
    assert.ok(error instanceof LinuxCloudflareAuthenticationRefusal);
    assert.equal(error.code, "AUTHORIZATION_UNAVAILABLE");
    assert.equal(error.toJSON().credentialReturned, false);
    return true;
  });
  assert.deepEqual(calls.map(({ args }) => args), [
    ["--version"],
    ["whoami", "--json", "--account", accountId]
  ]);
});

test("inspection reports an existing profile that is not bound without mutating Wrangler state", async (t) => {
  const directory = await testDirectory(t);
  await assert.rejects(inspectLinuxCloudflareAuthentication({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, {
    directoryBindingsPath: join(directory, "absent-bindings.json"),
    execute: async () => ({ stdout: "secret-tool (libsecret-tools)", stderr: "" })
  }), (error) => error instanceof LinuxCloudflareAuthenticationRefusal && error.code === "PROFILE_NOT_BOUND");
});

test("authentication removes its disposable profile binding", async (t) => {
  const directory = await testDirectory(t);
  const calls = [];
  const execute = async (_command, args) => {
    calls.push(args);
    if (args.includes("whoami")) return {
      stdout: JSON.stringify({ loggedIn: true, accounts: [{ id: accountId }], tokenPermissions: ["account:read", "offline_access"] }),
      stderr: ""
    };
    return { stdout: "", stderr: "" };
  };
  await authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, { wranglerConfigDirectory: join(directory, ".wrangler"), environment: { HOME: directory }, execute, wranglerPath: "/cell/wrangler" });
  assert.ok(calls.some((args) => args[0] === "auth" && args[1] === "deactivate"));
});

