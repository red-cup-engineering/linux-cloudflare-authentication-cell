import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createWindowsCurrentUserDpapiSecretTool } from "../libexec/windows-dpapi-secret-tool.mjs";

test("one Wrangler profile round-trips only through its CurrentUser DPAPI coordinate", async () => {
  const root = await mkdtemp(join(tmpdir(), "windows-dpapi-secret-tool-"));
  const entropy = [];
  const protect = async (plaintext, coordinate) => {
    entropy.push(coordinate);
    return Buffer.concat([Buffer.from("sealed:"), createHash("sha256").update(coordinate).digest(), Buffer.from(plaintext).reverse()]);
  };
  const unprotect = async (ciphertext, coordinate) => {
    assert.deepEqual(ciphertext.subarray(7, 39), createHash("sha256").update(coordinate).digest());
    return Buffer.from(ciphertext.subarray(39)).reverse();
  };
  const tool = createWindowsCurrentUserDpapiSecretTool({ root, protect, unprotect });
  const attributes = { service: "wrangler", account: "bare-cedar-fog-semantic-content-identity" };
  const secret = Buffer.from('{"key":"must-never-be-plaintext-on-disk"}');
  await tool.store(attributes, secret);
  const [path] = await readdir(root);
  const stored = await readFile(join(root, path));
  assert.equal(stored.includes(secret), false);
  assert.equal((await stat(join(root, path))).mode & 0o777, 0o600);
  assert.deepEqual(await tool.lookup(attributes), secret);
  assert.equal(entropy.length, 1);
  assert.match(entropy[0], /service=wrangler\|account=bare-cedar-fog-semantic-content-identity$/u);
  assert.equal(await tool.lookup({ ...attributes, account: "foreign-profile" }), null);
  await tool.clear(attributes);
  assert.equal(await tool.lookup(attributes), null);
});
