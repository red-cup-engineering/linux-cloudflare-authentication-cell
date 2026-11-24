import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";

export const CLOUDFLARE_OAUTH = Object.freeze({
  authorizationEndpoint: "https://dash.cloudflare.com/oauth2/auth",
  tokenEndpoint: "https://dash.cloudflare.com/oauth2/token",
  accountsEndpoint: "https://api.cloudflare.com/client/v4/accounts",
  clientId: "54d11594-84e4-41aa-b438-e81b8fa78ee7",
  redirectUri: "http://localhost:8976/oauth/callback"
});

const TOKEN_ATTEMPTS = 2;

export class CloudflareOAuthRefusal extends Error {
  constructor(code, message, evidence = {}) {
    super(message);
    this.name = "CloudflareOAuthRefusal";
    this.code = code;
    this.evidence = Object.freeze({ ...evidence });
  }
}

function opaque(bytes) {
  return randomBytes(bytes).toString("base64url");
}

function exactScopes(value, requested) {
  const granted = [...new Set(String(value ?? "").split(/\s+/u).filter(Boolean))].sort();
  const expected = [...new Set([...requested, "offline_access"])].sort();
  if (JSON.stringify(granted) !== JSON.stringify(expected)) {
    throw new CloudflareOAuthRefusal("OAUTH_SCOPE_MISMATCH", "Cloudflare granted a scope set different from the exact request", { expected, granted });
  }
  return granted;
}

function jsonObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CloudflareOAuthRefusal("OAUTH_RESPONSE_INVALID", "OAuth provider returned a non-object response");
  }
  return value;
}

async function readJson(fetchImpl, url, init) {
  try {
    const response = await fetchImpl(url, init);
    let body;
    try {
      body = jsonObject(await response.json());
    } catch (error) {
      if (error instanceof CloudflareOAuthRefusal) throw error;
      throw new CloudflareOAuthRefusal("OAUTH_RESPONSE_INVALID", "OAuth provider returned unreadable JSON", { status: response.status });
    }
    return { status: response.status, ok: response.ok, body };
  } catch (error) {
    if (error instanceof CloudflareOAuthRefusal) throw error;
    throw new CloudflareOAuthRefusal("OAUTH_TRANSPORT_FAILED", "OAuth transport failed without returning a response");
  }
}

async function exchangeCode(input, options) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirectUri,
    client_id: input.clientId,
    code_verifier: input.verifier
  }).toString();
  let lastError;
  for (let attempt = 1; attempt <= options.attempts; attempt += 1) {
    try {
      const result = await readJson(options.fetchImpl, input.tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body
      });
      if (!result.ok) {
        const retryable = result.status === 429 || result.status >= 500;
        if (retryable && attempt < options.attempts) continue;
        throw new CloudflareOAuthRefusal("OAUTH_TOKEN_EXCHANGE_REFUSED", "Cloudflare refused the authorization-code exchange", { status: result.status, attempt });
      }
      return { ...result.body, attempts: attempt };
    } catch (error) {
      lastError = error;
      const retryable = error instanceof CloudflareOAuthRefusal && error.code === "OAUTH_TRANSPORT_FAILED";
      if (!retryable || attempt === options.attempts) throw error;
    }
  }
  throw lastError;
}

function awaitCallback({ host, port, path, expectedState }) {
  let server;
  const callback = new Promise((resolve, reject) => {
    const finish = (error, value) => {
      server.close(() => error ? reject(error) : resolve(value));
    };
    server = createServer((request, response) => {
      const url = new URL(request.url ?? "/", `http://${host}:${port}`);
      if (request.method === "GET" && url.pathname === "/__cloudflare_auth_callback_ipv4_probe") {
        response.writeHead(204, { connection: "close", "cache-control": "no-store" }).end();
        return;
      }
      if (request.method !== "GET" || url.pathname !== path) {
        response.writeHead(404).end();
        return;
      }
      if (url.searchParams.get("state") !== expectedState) {
        response.writeHead(400, { "content-type": "text/plain; charset=utf-8", connection: "close" }).end("Authorization state mismatch.");
        finish(new CloudflareOAuthRefusal("OAUTH_STATE_MISMATCH", "OAuth callback state did not match the issued state"));
        return;
      }
      const providerError = url.searchParams.get("error");
      const code = url.searchParams.get("code");
      if (providerError || !code) {
        response.writeHead(400, { "content-type": "text/plain; charset=utf-8", connection: "close" }).end("Authorization was not granted.");
        finish(new CloudflareOAuthRefusal("OAUTH_CALLBACK_REFUSED", "Cloudflare callback did not carry an authorization code", { providerError: providerError ?? null }));
        return;
      }
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8", connection: "close" }).end("Authorization received. You may close this tab.");
      finish(null, code);
    });
    server.once("error", (error) => reject(new CloudflareOAuthRefusal("OAUTH_CALLBACK_BIND_FAILED", "OAuth callback listener could not bind", { cause: error.code ?? "unknown" })));
    server.listen(port, host);
  });
  return { callback, listening: new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  }), close: () => server?.close() };
}

export async function authorizeCloudflareWithPkce(input, options = {}) {
  const endpoints = { ...CLOUDFLARE_OAUTH, ...options.endpoints };
  const fetchImpl = options.fetchImpl ?? fetch;
  const state = opaque(32);
  const verifier = opaque(72);
  const challenge = createHash("sha256").update(verifier, "ascii").digest("base64url");
  const redirect = new URL(endpoints.redirectUri);
  const callback = awaitCallback({
    host: input.callbackHost,
    port: input.callbackPort,
    path: redirect.pathname,
    expectedState: state
  });
  await callback.listening;
  await options.preflightCallback?.({
    url: `http://localhost:${input.callbackPort}/__cloudflare_auth_callback_ipv4_probe`,
    registeredRedirectUri: endpoints.redirectUri
  });
  const callbackResult = callback.callback;
  callbackResult.catch(() => {});
  const authorizationUrl = new URL(endpoints.authorizationEndpoint);
  authorizationUrl.search = new URLSearchParams({
    response_type: "code",
    client_id: endpoints.clientId,
    redirect_uri: endpoints.redirectUri,
    scope: [...input.scopes, "offline_access"].join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  }).toString();
  try {
    await (options.openBrowser)(authorizationUrl.toString());
    const code = await callbackResult;
    const token = await exchangeCode({
      code,
      verifier,
      redirectUri: endpoints.redirectUri,
      clientId: endpoints.clientId,
      tokenEndpoint: endpoints.tokenEndpoint
    }, {
      fetchImpl,
      attempts: options.tokenAttempts ?? TOKEN_ATTEMPTS
    });
    if (typeof token.access_token !== "string" || token.access_token === ""
        || !Number.isFinite(token.expires_in) || token.expires_in <= 0) {
      throw new CloudflareOAuthRefusal("OAUTH_TOKEN_RESPONSE_INVALID", "Cloudflare token response omitted required fields");
    }
    const scopes = exactScopes(token.scope, input.scopes);
    const accounts = await readJson(fetchImpl, endpoints.accountsEndpoint, {
      headers: { authorization: `Bearer ${token.access_token}` }
    });
    const member = Array.isArray(accounts.body.result) && accounts.body.result.some((account) => account?.id === input.expectedAccountId);
    if (!accounts.ok || !member) {
      throw new CloudflareOAuthRefusal("OAUTH_ACCOUNT_MISMATCH", "OAuth identity is not a member of the expected Cloudflare account", { expectedAccountId: input.expectedAccountId, status: accounts.status });
    }
    const authority = await options.storeCredential({
      profile: input.profile,
      oauthToken: token.access_token,
      expirationTime: new Date((options.now ?? Date.now)() + token.expires_in * 1000).toISOString(),
      refreshToken: typeof token.refresh_token === "string" ? token.refresh_token : undefined,
      scopes
    });
    return Object.freeze({ account: { id: input.expectedAccountId }, scopes: input.scopes, tokenAttempts: token.attempts, authority: authority ?? null, credentialReturned: false, verified: true });
  } finally {
    callback.close();
  }
}
