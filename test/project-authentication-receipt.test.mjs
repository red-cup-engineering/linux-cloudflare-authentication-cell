import test from "node:test";
import assert from "node:assert/strict";
import { extractRmnActivity } from "@red-cup-engineering/activitypub-services-section/rmn-activity";
import { decodeReceiptRmn } from "@red-cup-engineering/typed-resource-catalog/rmn";
import { semanticId } from "@red-cup-engineering/typed-resource-catalog";
import {
  AUTHENTICATION_ACTIVITY_IDENTIFIER,
  AUTHENTICATION_ACTIVITY_ORIGIN,
  AUTHENTICATION_AGENT_CARD,
  projectAuthenticationReceipt
} from "../src/project-authentication-receipt.mjs";

const receiptBody = Object.freeze({
  type: "LinuxCloudflareAuthenticationReceipt",
  profile: "bare-cedar-fog",
  account: Object.freeze({ id: "0123456789abcdef0123456789abcdef" }),
  scopes: Object.freeze(["account:read"]),
  settlementDirectory: "/projection/bare-cedar-fog",
  credentialCustody: "linux-secret-service",
  authority: Object.freeze({
    profile: "org.red-cup-engineering.opaque-authority-reference.v1",
    type: "OpaqueAuthorityReference",
    reference: "urn:authority:one",
    content: `ni:///sha-256;${"A".repeat(43)}`,
    secretBytesReturned: false
  }),
  credentialReturned: false,
  verified: true
});
const receipt = Object.freeze({ ...receiptBody, id: semanticId(receiptBody) });

test("the settled authority receipt has one deterministic RMN/ActivityPub projection", () => {
  const first = projectAuthenticationReceipt(receipt);
  const second = projectAuthenticationReceipt(structuredClone(receipt));
  assert.deepEqual(second, first);
  assert.equal(first.activity.id, second.activity.id);

  const extracted = extractRmnActivity(first.activity, {
    expectedActor: new URL(`/actors/${AUTHENTICATION_ACTIVITY_IDENTIFIER}`, AUTHENTICATION_ACTIVITY_ORIGIN).href,
    expectedRecipient: "https://www.w3.org/ns/activitystreams#Public",
    expectedAgentCard: AUTHENTICATION_AGENT_CARD
  });
  assert.equal(extracted.a2aMessage.role, "ROLE_AGENT");
  assert.equal(extracted.a2aMessage.parts.length, 1);
  assert.equal(extracted.a2aMessage.parts[0].metadata.ni, extracted.objectNi);
  assert.equal("capabilityOperation" in extracted.a2aMessage.metadata, false);
  assert.equal(JSON.stringify(first.activity).includes("captp"), false);
  assert.equal(JSON.stringify(first.activity).includes("x402"), false);
  assert.deepEqual(decodeReceiptRmn(extracted.objectBytes), receipt);
});

test("neither the RMN Mark nor its public activity can carry credential bytes", () => {
  const secret = "oauth-access-token-that-must-never-cross";
  const projection = projectAuthenticationReceipt(receipt);
  assert.equal(JSON.stringify(projection).includes(secret), false);
  assert.throws(
    () => projectAuthenticationReceipt({ ...receipt, credential: secret }),
    /unprojectable field: credential/u
  );
});
