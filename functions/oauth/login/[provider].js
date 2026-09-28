import { generateRandomString, calculateHash } from "../../_shared/crypto.js";
import { txCookie } from "../../_shared/cookies.js";

export async function onRequestGet(context) {
  const provider = context.params.provider;
  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404, headers: { "Cache-Control": "no-store" } });
  }

  const env = context.env;
  const transactionId = generateRandomString();
  const state = generateRandomString();
  const codeVerifier = generateRandomString();
  const nonce = provider === "google" ? generateRandomString() : null;

  const idHash = await calculateHash(transactionId);
  const stateHash = await calculateHash(state);
  const codeChallenge = await calculateHash(codeVerifier);
  const now = Math.floor(Date.now() / 1000);

  // limpeza de transacoes vencidas
  await env.DB.prepare("DELETE FROM oauth_transactions WHERE expires_at < ?").bind(now).run();

  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(idHash, provider, stateHash, nonce, codeVerifier, now + 600).run();

  const clientId = provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;

  const authUrl = new URL(
    provider === "google"
      ? "https://accounts.google.com/o/oauth2/v2/auth"
      : "https://github.com/login/oauth/authorize"
  );
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("nonce", nonce);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": txCookie(transactionId),
      "Cache-Control": "no-store",
    },
  });
}
