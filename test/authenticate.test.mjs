import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { authenticateLinuxColonyWithCloudflare, validateAuthenticationRequest } from "../src/authenticate-linux-colony-with-cloudflare.mjs";

const accountId = "0123456789abcdef0123456789abcdef";

test("refuses implicit and unknown authority", () => {
  assert.throws(() => validateAuthenticationRequest({ profile: "union", expectedAccountId: accountId, scopes: [], settlementDirectory: "/" }), /non-empty/);
  assert.throws(() => validateAuthenticationRequest({ profile: "union", expectedAccountId: accountId, scopes: ["dns:edit"], settlementDirectory: "/" }), /unsupported/);
});

test("authorizes, verifies, then activates without ambient credentials", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cloudflare-auth-cell-"));
  const expectedDirectory = await realpath(directory);
  const calls = [];
  const execute = async (command, args, options) => {
    calls.push({ command, args, options });
    if (calls.length === 1) throw new Error("profile absent");
    if (args.includes("whoami")) return { stdout: JSON.stringify({ accounts: [{ id: accountId, name: "Union" }], tokenPermissions: ["offline_access", "workers_scripts:write", "account:read"] }), stderr: "" };
    return { stdout: "", stderr: "" };
  };
  const receipt = await authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["workers_scripts:write", "account:read"],
    settlementDirectory: directory,
    browser: false
  }, {
    execute,
    wranglerPath: "/cell/wrangler",
    compatibilityDirectory: "/cell/libexec",
    environment: {
      PATH: "/usr/bin",
      CLOUDFLARE_API_TOKEN: "must-not-cross",
      CLOUDFLARE_API_KEY: "must-not-cross"
    }
  });

  assert.equal(calls.length, 5);
  assert.deepEqual(calls[1].args, [
    "auth", "create", "bare-cedar-fog", "--scopes", "account:read",
    "workers_scripts:write", "--callback-host", "localhost", "--callback-port",
    "8976", "--no-browser"
  ]);
  assert.equal(calls[2].args[0], "auth");
  assert.equal(calls[2].args[1], "activate");
  assert.deepEqual(calls[3].args, ["whoami", "--json", "--account", accountId]);
  assert.deepEqual(calls[4].args, ["auth", "activate", "bare-cedar-fog", expectedDirectory]);
  assert.equal(calls[1].options.env.CLOUDFLARE_AUTH_USE_KEYRING, "true");
  assert.equal(calls[1].options.env.CLOUDFLARE_API_TOKEN, undefined);
  assert.equal(calls[1].options.env.CLOUDFLARE_API_KEY, undefined);
  assert.equal(receipt.credentialReturned, false);
  assert.equal(JSON.stringify(receipt).includes("must-not-cross"), false);
});

test("does not activate an unexpected account", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cloudflare-auth-cell-"));
  let calls = 0;
  await assert.rejects(authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory
  }, {
    execute: async (_command, args) => {
      calls += 1;
      if (args.includes("whoami")) return { stdout: JSON.stringify({ accounts: [{ id: "f".repeat(32) }], tokenPermissions: ["account:read", "offline_access"] }), stderr: "" };
      return { stdout: "", stderr: "" };
    }
  }), /not a member/);
  assert.equal(calls, 5);
});

test("does not reuse a profile carrying broader authority", async () => {
  const directory = await mkdtemp(join(tmpdir(), "cloudflare-auth-cell-"));
  let calls = 0;
  await assert.rejects(authenticateLinuxColonyWithCloudflare({
    profile: "bare-cedar-fog",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    settlementDirectory: directory,
    browser: false
  }, {
    execute: async (_command, args) => {
      calls += 1;
      if (args.includes("whoami")) {
        return { stdout: JSON.stringify({
          accounts: [{ id: accountId }],
          tokenPermissions: ["account:read", "offline_access", "workers:write"]
        }), stderr: "" };
      }
      return { stdout: "", stderr: "" };
    }
  }), /granted OAuth permissions differ/);
  assert.equal(calls, 5);
});
