#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { authenticateLinuxColonyWithCloudflare } from "../src/authenticate-linux-colony-with-cloudflare.mjs";

const usage = "usage: authenticate-linux-colony-with-cloudflare REQUEST.json";
const path = process.argv[2];
if (!path || process.argv.length !== 3) {
  console.error(usage);
  process.exitCode = 64;
} else {
  try {
    const request = JSON.parse(await readFile(path, "utf8"));
    const receipt = await authenticateLinuxColonyWithCloudflare(request, {
      onProgress(event) {
        process.stderr.write(`[${event.phase}] ${event.message}\n`);
      }
    });
    process.stdout.write(`${JSON.stringify(receipt)}\n`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
