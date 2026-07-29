import assert from "node:assert/strict";
import test from "node:test";
import { reconcileCloudRunDomainMappingDns } from "../src/authenticate-linux-colony-with-cloudflare.mjs";

const input = { authentication: { profile: "named-profile", expectedAccountId: "0123456789abcdef0123456789abcdef", scopes: ["account:read", "dns:write"], settlementDirectory: "/tmp", browser: true }, mapping: { zone: "561.group", type: "CNAME", name: "gui.561.group", content: "ghs.googlehosted.com", proxied: false, ttl: 1 } };
const response = (result) => ({ ok: true, json: async () => ({ success: true, result }) });
function fixture(records = []) {
  const calls = [];
  const fetch = async (url, init = {}) => { calls.push({ url, init }); if (url.endsWith("/zones?name=561.group")) return response([{ id: "zone", name: "561.group" }]); if (init.method === "POST") return response({ id: "created" }); if (init.method === "PUT") return response({ id: "updated" }); return response(records); };
  return { calls, fetch };
}
const options = (fetch) => ({ fetch, inspect: async () => ({ verified: true, credentialReturned: false }), profileCredential: async () => ({ oauthToken: "secret" }) });

test("reconciles the exact Cloud Run CNAME idempotently", async () => {
  const missing = fixture(), created = await reconcileCloudRunDomainMappingDns(input, options(missing.fetch));
  assert.equal(created.disposition, "created"); assert.equal(missing.calls[2].init.method, "POST");
  const exact = fixture([{ id: "exact", ...input.mapping }]), unchanged = await reconcileCloudRunDomainMappingDns(input, options(exact.fetch));
  assert.equal(unchanged.disposition, "unchanged"); assert.equal(exact.calls.length, 2);
});
test("updates one divergent record and refuses duplicate records", async () => {
  const divergent = fixture([{ id: "old", ...input.mapping, content: "old.example" }]), updated = await reconcileCloudRunDomainMappingDns(input, options(divergent.fetch));
  assert.equal(updated.disposition, "updated"); assert.equal(divergent.calls[2].init.method, "PUT");
  const duplicate = fixture([{ id: "one", ...input.mapping }, { id: "two", ...input.mapping }]);
  await assert.rejects(reconcileCloudRunDomainMappingDns(input, options(duplicate.fetch)), /duplicate/u);
});
