import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { once } from "node:events";
import {
  authorizeCloudflareWithPkce,
  CloudflareOAuthRefusal
} from "../src/cloudflare-oauth-pkce.mjs";

const accountId = "0123456789abcdef0123456789abcdef";
const accessToken = "test-access-secret-never-in-receipt";
const refreshToken = "test-refresh-secret-never-in-receipt";

async function fakeProvider({ grantedScopes = "account:read offline_access", accounts = [{ id: accountId }] } = {}) {
  let challenge;
  let tokenRequests = 0;
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://provider.invalid");
    if (url.pathname === "/authorize") {
      challenge = url.searchParams.get("code_challenge");
      const callback = new URL(url.searchParams.get("redirect_uri"));
      callback.searchParams.set("code", "fake-code");
      callback.searchParams.set("state", url.searchParams.get("state"));
      response.writeHead(302, { location: callback.toString() }).end();
      return;
    }
    if (url.pathname === "/token") {
      tokenRequests += 1;
      let body = "";
      for await (const chunk of request) body += chunk;
      const form = new URLSearchParams(body);
      assert.equal(createHash("sha256").update(form.get("code_verifier"), "ascii").digest("base64url"), challenge);
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        access_token: accessToken,
        refresh_token: refreshToken,
        expires_in: 3600,
        scope: grantedScopes
      }));
      return;
    }
    if (url.pathname === "/accounts") {
      assert.equal(request.headers.authorization, `Bearer ${accessToken}`);
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ result: accounts }));
      return;
    }
    response.writeHead(404).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  return {
    endpoints: {
      authorizationEndpoint: `http://127.0.0.1:${port}/authorize`,
      tokenEndpoint: `http://127.0.0.1:${port}/token`,
      accountsEndpoint: `http://127.0.0.1:${port}/accounts`,
      clientId: "fake-public-client"
    },
    tokenRequests: () => tokenRequests,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

async function settlement(provider, overrides = {}) {
  const callbackProbe = createServer();
  callbackProbe.listen(0, "127.0.0.1");
  await once(callbackProbe, "listening");
  const callbackPort = callbackProbe.address().port;
  await new Promise((resolve) => callbackProbe.close(resolve));
  const stored = [];
  const endpoints = { ...provider.endpoints, redirectUri: `http://127.0.0.1:${callbackPort}/oauth/callback` };
  const receipt = await authorizeCloudflareWithPkce({
    profile: "test-profile",
    expectedAccountId: accountId,
    scopes: ["account:read"],
    callbackHost: "127.0.0.1",
    callbackPort
  }, {
    endpoints,
    tokenAttempts: overrides.tokenAttempts ?? 2,
    now: overrides.now,
    preflightCallback: overrides.preflightCallback,
    storeCredential: async (credential) => { stored.push(credential); },
    openBrowser: overrides.openBrowser ?? (async (url) => {
      const response = await fetch(url);
      assert.equal(response.status, 200);
    })
  });
  return { receipt, stored };
}

test("cell owns PKCE callback, verifies, and returns no secrets", async () => {
  const provider = await fakeProvider();
  try {
    const { receipt, stored } = await settlement(provider, { now: () => Date.parse("2026-07-29T18:00:00.000Z") });
    assert.equal(provider.tokenRequests(), 1);
    assert.equal(stored.length, 1);
    assert.equal(stored[0].oauthToken, accessToken);
    assert.equal(stored[0].expirationTime, "2026-07-29T19:00:00.000Z");
    assert.equal(stored[0].refreshToken, refreshToken);
    assert.equal(receipt.verified, true);
    assert.equal(receipt.tokenAttempts, 1);
    assert.equal(JSON.stringify(receipt).includes(accessToken), false);
    assert.equal(JSON.stringify(receipt).includes(refreshToken), false);
  } finally {
    await provider.close();
  }
});

test("browser transfer is direct and does not depend on provider output or newlines", async () => {
  const provider = await fakeProvider();
  let transferred;
  try {
    await settlement(provider, { openBrowser: async (url) => {
      transferred = new URL(url);
      await fetch(url);
    } });
    assert.equal(transferred.searchParams.get("code_challenge_method"), "S256");
    assert.equal(transferred.searchParams.has("state"), true);
  } finally {
    await provider.close();
  }
});

test("callback reachability is proved before the browser receives the authorization URL", async () => {
  const provider = await fakeProvider();
  const transitions = [];
  try {
    await settlement(provider, {
      preflightCallback: async ({ url, registeredRedirectUri }) => {
        transitions.push("preflight");
        assert.match(url, /\/__cloudflare_auth_callback_ipv4_probe$/u);
        assert.match(registeredRedirectUri, /\/oauth\/callback$/u);
        assert.equal((await fetch(url)).status, 204);
      },
      openBrowser: async (url) => {
        transitions.push("browser");
        assert.equal((await fetch(url)).status, 200);
      }
    });
    assert.deepEqual(transitions, ["preflight", "browser"]);
  } finally {
    await provider.close();
  }
});

test("state, exact scopes, and expected account are independently enforced", async () => {
  const stateProvider = await fakeProvider();
  try {
    await assert.rejects(settlement(stateProvider, { openBrowser: async (url) => {
      const authorization = new URL(url);
      const callback = new URL(authorization.searchParams.get("redirect_uri"));
      callback.searchParams.set("code", "fake-code");
      callback.searchParams.set("state", "wrong-state");
      await fetch(callback);
    } }), (error) => error instanceof CloudflareOAuthRefusal && error.code === "OAUTH_STATE_MISMATCH");
  } finally { await stateProvider.close(); }

  const scopeProvider = await fakeProvider({ grantedScopes: "account:read workers:write offline_access" });
  try {
    await assert.rejects(settlement(scopeProvider), (error) => error instanceof CloudflareOAuthRefusal && error.code === "OAUTH_SCOPE_MISMATCH");
  } finally { await scopeProvider.close(); }

  const accountProvider = await fakeProvider({ accounts: [{ id: "f".repeat(32) }] });
  try {
    await assert.rejects(settlement(accountProvider), (error) => error instanceof CloudflareOAuthRefusal && error.code === "OAUTH_ACCOUNT_MISMATCH");
  } finally { await accountProvider.close(); }
});
