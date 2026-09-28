import { calculateHash, generateRandomString } from "../../_shared/crypto.js";
import { getCookie, clearTxCookie, sessionCookie } from "../../_shared/cookies.js";
import { validateGoogleToken } from "../../_shared/oidc.js";
import { validateGithubUser } from "../../_shared/providers.js";
 
const NO_STORE = { "Cache-Control": "no-store" };
 
function fail(message, status = 400) {
  const headers = new Headers(NO_STORE);
  headers.append("Set-Cookie", clearTxCookie);
  return new Response(message, { status, headers });
}
 
export async function onRequestGet(context) {
  const provider = context.params.provider;
  if (provider !== "google" && provider !== "github") {
    return new Response("Not Found", { status: 404, headers: NO_STORE });
  }
 
  const env = context.env;
  const db = env.DB;
  const url = new URL(context.request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
 
  // 1. error ou ausencia de code/state
  if (url.searchParams.get("error") || !code || !state) {
    return fail("Faltam parametros ou provedor retornou erro.");
  }
 
  // 2. cookie de transacao
  const txValue = getCookie(context.request, "__Host-oauth-tx");
  if (!txValue) return fail("Transacao ausente.");
 
  // 3. localizar transacao valida
  const idHash = await calculateHash(txValue);
  const now = Math.floor(Date.now() / 1000);
  const tx = await db
    .prepare("SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?")
    .bind(idHash, provider, now)
    .first();
  if (!tx) return fail("Transacao ausente ou expirada.");
 
  // 5. apagar a transacao antes de concluir (mesmo se o state estiver errado)
  await db.prepare("DELETE FROM oauth_transactions WHERE id_hash = ?").bind(idHash).run();
 
  // 4. comparar state
  const stateHash = await calculateHash(state);
  if (stateHash !== tx.state_hash) return fail("State invalido.");
 
  // 6 e 7. trocar o codigo e confirmar identidade
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  let identity;
  try {
    if (provider === "google") {
      const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id: env.GOOGLE_CLIENT_ID,
          client_secret: env.GOOGLE_CLIENT_SECRET,
          code,
          grant_type: "authorization_code",
          redirect_uri: redirectUri,
          code_verifier: tx.code_verifier,
        }),
      });
      if (!res.ok) throw new Error("token_exchange");
      const tokens = await res.json();
      identity = await validateGoogleToken(tokens.id_token, env.GOOGLE_CLIENT_ID, tx.nonce);
    } else {
      const res = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "oauth-pages-lab" },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
          code_verifier: tx.code_verifier,
        }),
      });
      if (!res.ok) throw new Error("token_exchange");
      const tokens = await res.json();
      if (!tokens.access_token || String(tokens.token_type).toLowerCase() !== "bearer") {
        throw new Error("token_response");
      }
      identity = await validateGithubUser(tokens.access_token, env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET);
    }
  } catch (err) {
    // nao expor detalhes internos nem corpos de resposta
    return fail("Falha na validacao da identidade.", 401);
  }
 
  // 8. sessao opaca (8 horas)
  const sessionId = generateRandomString();
  const sessionHash = await calculateHash(sessionId);
  await db
    .prepare(
      `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(sessionHash, identity.issuer, identity.subject, identity.email, identity.name, now + 28800, now)
    .run();
 
  // 9 e 10. limpar cookie temporario e redirecionar
  const headers = new Headers(NO_STORE);
  headers.set("Location", env.PUBLIC_BASE_URL);
  headers.append("Set-Cookie", sessionCookie(sessionId));
  headers.append("Set-Cookie", clearTxCookie);
  return new Response(null, { status: 302, headers });
}
