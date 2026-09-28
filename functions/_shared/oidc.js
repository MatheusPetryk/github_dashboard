import { base64UrlToBytes } from "./crypto.js";

const GOOGLE_ISSUER = "https://accounts.google.com";

function decodeJson(part) {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(part)));
}

export async function validateGoogleToken(idToken, clientId, expectedNonce) {
  // 1. Tres partes
  const parts = typeof idToken === "string" ? idToken.split(".") : [];
  if (parts.length !== 3) throw new Error("jwt_format");

  const header = decodeJson(parts[0]);
  const payload = decodeJson(parts[1]);

  // 2. alg RS256
  if (header.alg !== "RS256") throw new Error("jwt_alg");

  // 3 e 4. Descoberta OIDC e JWKS
  const discovery = await (await fetch(`${GOOGLE_ISSUER}/.well-known/openid-configuration`)).json();
  if (discovery.issuer !== GOOGLE_ISSUER) throw new Error("issuer_discovery");
  const jwks = await (await fetch(discovery.jwks_uri)).json();

  // 5. Chave pelo kid
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("jwt_kid");

  // 6. Importar JWK
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  // 7. Verificar assinatura
  const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature = base64UrlToBytes(parts[2]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signedData);
  if (!ok) throw new Error("jwt_signature");

  // 8. iss, aud, exp, iat, nonce
  const now = Math.floor(Date.now() / 1000);
  const skew = 60;
  if (payload.iss !== GOOGLE_ISSUER) throw new Error("jwt_iss");
  if (payload.aud !== clientId) throw new Error("jwt_aud");
  if (typeof payload.exp !== "number" || payload.exp <= now - skew) throw new Error("jwt_exp");
  if (typeof payload.iat !== "number" || payload.iat > now + skew) throw new Error("jwt_iat");
  if (!expectedNonce || payload.nonce !== expectedNonce) throw new Error("jwt_nonce");
  if (!payload.sub) throw new Error("jwt_sub");

  return {
    issuer: GOOGLE_ISSUER,
    subject: payload.sub,
    email: payload.email ?? null,
    name: payload.name ?? null,
  };
}
