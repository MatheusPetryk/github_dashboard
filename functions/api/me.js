
import { calculateHash } from "../_shared/crypto.js";
import { getCookie } from "../_shared/cookies.js";

const NO_STORE = { "Cache-Control": "no-store" };

export async function onRequestGet(context) {
  const sessionValue = getCookie(context.request, "__Host-session");
  if (!sessionValue) {
    return Response.json({ error: "unauthenticated" }, { status: 401, headers: NO_STORE });
  }

  const idHash = await calculateHash(sessionValue);
  const now = Math.floor(Date.now() / 1000);
  const session = await context.env.DB
    .prepare("SELECT issuer, email, display_name FROM sessions WHERE id_hash = ? AND expires_at > ?")
    .bind(idHash, now)
    .first();

  if (!session) {
    return Response.json({ error: "unauthenticated" }, { status: 401, headers: NO_STORE });
  }

  // perfil minimo
  return Response.json(
    { issuer: session.issuer, email: session.email, displayName: session.display_name },
    { headers: NO_STORE }
  );
}
