import test from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthorityCustodyActuator } from "@red-cup-engineering/authority-custody-actuator";
import { createWranglerKeyringAuthoritySubstrate } from "../src/wrangler-keyring-authority-substrate.mjs";

test("shared actuator projects opaque Cloudflare authority through Wrangler keyring custody", async () => {
  const configDirectory = await mkdtemp(join(tmpdir(), "wrangler-authority-substrate-"));
  let keyEnvelope;
  let cleared = false;
  const secretToolExecute = async (args, input) => {
    if (args[0] === "lookup") return keyEnvelope ? { status: 0, stdout: keyEnvelope } : { status: 1, stdout: "" };
    if (args[0] === "store") { keyEnvelope = input; return { status: 0, stdout: "" }; }
    if (args[0] === "clear") { keyEnvelope = undefined; cleared = true; return { status: 0, stdout: "" }; }
    return { status: 64, stdout: "" };
  };
  const substrate = createWranglerKeyringAuthoritySubstrate({ configDirectory, secretToolExecute });
  const custody = createAuthorityCustodyActuator({ substrate, referenceFactory: () => "urn:authority:test-cloudflare", clock: () => "2026-07-29T00:00:00.000Z" });
  const secret = {
    profile: "test-profile",
    oauthToken: "access-secret",
    expirationTime: "2026-07-29T01:00:00.000Z",
    refreshToken: "refresh-secret",
    scopes: ["account:read", "offline_access"]
  };
  const receipt = await custody.store({ provider: "cloudflare", subject: secret.profile, attributes: { scopes: secret.scopes }, secret });
  const encryptedPath = join(configDirectory, "config", "test-profile.enc");
  const envelope = JSON.parse(await readFile(encryptedPath, "utf8"));
  assert.equal(envelope.v, 1);
  assert.equal(envelope.alg, "AES-256-GCM");
  assert.equal(JSON.stringify(envelope).includes(secret.oauthToken), false);
  assert.equal((await stat(encryptedPath)).mode & 0o777, 0o600);
  await assert.rejects(access(join(configDirectory, "config", "test-profile.toml")));
  assert.equal(receipt.content.startsWith("ni:///sha-256;"), true);
  assert.equal(receipt.secretBytesReturned, false);
  assert.equal(JSON.stringify(receipt).includes(secret.oauthToken), false);
  assert.deepEqual(await substrate.readProfile(secret.profile), secret);
  assert.deepEqual(await custody.retrieve(receipt.reference), secret);
  const revocation = await custody.revoke(receipt.reference);
  assert.equal(revocation.secretBytesReturned, false);
  assert.equal(cleared, true);
  await assert.rejects(access(encryptedPath));
});
