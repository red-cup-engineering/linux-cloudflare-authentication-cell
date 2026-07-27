#!/usr/bin/env node
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRml, semanticBytes, semanticId } from "@lenticule-science/rmn-semantic-conformance-die";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "content/contracts/authenticate-linux-colony-with-cloudflare.rml");
const manifest = parseRml(readFileSync(source, "utf8"));
const bytes = semanticBytes(manifest);
const id = semanticId(manifest);
const directory = resolve(root, "data/manifest");
mkdirSync(directory, { recursive: true });
writeFileSync(resolve(directory, "manifest.rmn.cbor"), bytes);
writeFileSync(resolve(directory, "receipt.json"), `${JSON.stringify({
  type: "CapabilityCellManifestMaterialized",
  manifest: id,
  mediaType: "application/rmn+cbor",
  byteLength: bytes.length
}, null, 2)}\n`);
process.stdout.write(`${id}\n`);
