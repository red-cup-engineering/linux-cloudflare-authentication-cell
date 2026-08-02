import { semanticBytes } from "@red-cup-engineering/relation-model-notation-runtime";
import {
  ACTIVITYSTREAMS_PUBLIC,
  projectRmnActivity
} from "@red-cup-engineering/activitypub-services-section/rmn-activity";
import { receiptRmn } from "@red-cup-engineering/typed-resource-catalog/rmn";

export const AUTHENTICATION_ACTIVITY_ORIGIN = "https://linux-cloudflare-authentication.actions.561.group/";
export const AUTHENTICATION_ACTIVITY_IDENTIFIER = "linux-cloudflare-authentication";
export const AUTHENTICATION_AGENT_CARD = `${AUTHENTICATION_ACTIVITY_ORIGIN}.well-known/agent-card.json`;
const RECEIPT_FIELDS = new Set([
  "id", "type", "profile", "account", "scopes", "settlementDirectory",
  "credentialCustody", "authority", "credentialReturned", "verified"
]);

/**
 * Give one settled authentication receipt its existing RMN Mark and
 * ActivityPub faces. The Mark remains the semantic coordinate; canonical
 * CBOR is only the transport projection required by the public membrane.
 */
export function projectAuthenticationReceipt(receipt) {
  if (receipt?.type !== "LinuxCloudflareAuthenticationReceipt"
      || receipt.verified !== true || receipt.credentialReturned !== false) {
    throw new TypeError("one settled non-secret Cloudflare authentication receipt is required");
  }
  const foreignField = Object.keys(receipt).find((field) => !RECEIPT_FIELDS.has(field));
  if (foreignField !== undefined) {
    throw new TypeError(`Cloudflare authentication receipt contains an unprojectable field: ${foreignField}`);
  }
  const rmn = receiptRmn(receipt);
  const objectBytes = semanticBytes(rmn.term);
  const activity = projectRmnActivity({
    type: "Create",
    origin: AUTHENTICATION_ACTIVITY_ORIGIN,
    identifier: AUTHENTICATION_ACTIVITY_IDENTIFIER,
    recipient: ACTIVITYSTREAMS_PUBLIC,
    objectBytes,
    agentCard: AUTHENTICATION_AGENT_CARD
  });
  return Object.freeze({
    rmn: Object.freeze({
      mediaType: "application/rmn+cbor",
      semanticId: rmn.semanticId,
      term: rmn.term
    }),
    activity
  });
}
