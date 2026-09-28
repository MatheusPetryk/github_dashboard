import { calculateHash, generateRandomString } from "../../shared/crypto.js";
import { validateGoogleToken } from "../../shared/oidc.js";
import { validateGithubUser } from "../../shared/providers.js";

export async function onRequestGet(context) {
    const provider = context.params.provider;
    const requestUrl = new URL(context.request.url);
    
    const code = requestUrl.searchParams.get("code");
    const state = requestUrl.searchParams.get("state");
    const error = requestUrl.searchParams.get("error");

    if (error || !code || !state) {
        return new Response("Faltam parâmetros ou provedor retornou erro.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    const cookieHeader = context.request.headers.get("Cookie") || "";
    const txCookieMatch = cookieHeader.match(/(?:^|;\s*)__Host-oauth-tx=([^;]+)/) || cookieHeader.match(/(?:^|;\s*)Host-oauth-tx=([^;]+)/);
    
    if (!txCookieMatch) {
        return new Response("Cookie de transação ausente.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }
    const txCookie = txCookieMatch[1];
    const idHash = await calculateHash(txCookie);
    const db = context.env.DB;

    const tx = await db.prepare(`SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ?`).bind(idHash, provider).first();
    const now = Math.floor(Date.now() / 1000);

    if (!tx || now > tx.expires_at) {
        if (tx) await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();
        return new Response("Transação ausente ou expirada.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    const stateHash = await calculateHash(state);
    if (stateHash !== tx.state_hash) {
        await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();
        return new Response("State inválido. Possível ataque CSRF.", { status: 400, headers: { "Cache-Control": "no-store" } });
    }

    // Apagar a transação para evitar ataques de repetição
    await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();

    // 6. Trocar o código pelo token
    const clientId = context.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const clientSecret = context.env[`${provider.toUpperCase()}_CLIENT_SECRET`];
    const redirectUri = `\({context.env.PUBLIC_BASE_URL}/oauth/callback/\){provider}`;

    let identity;

    try {
        if (provider === 'google') {
            const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code: code,
                    grant_type: 'authorization_code',
                    redirect_uri: redirectUri,
                    code_verifier: tx.code_verifier
                })
            });
            if (!tokenRes.ok) throw new Error("Falha ao obter token do Google");
            const tokens = await tokenRes.json();
            identity = await validateGoogleToken(tokens.id_token, clientId, tx.nonce);
        } else {
            const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: clientId,
                    client_secret: clientSecret,
                    code: code,
                    redirect_uri: redirectUri
                })
            });
            if (!tokenRes.ok) throw new Error("Falha ao obter token do GitHub");
            const tokens = await tokenRes.json();
            identity = await validateGithubUser(tokens.access_token, clientId, clientSecret);
        }
    } catch (err) {
        return new Response(`Erro na validação: ${err.message}`, { status: 500 });
    }

    // 7. Criar a sessão local
    const sessionId = generateRandomString();
    const sessionHash = await calculateHash(sessionId);
    const expiresAt = now + (60 * 60 * 24 * 7); // 7 dias

    await db.prepare(
        `INSERT INTO sessions (id_hash, user_id, provider, email, name, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(sessionHash, identity.subject, provider, identity.email, identity.name, now, expiresAt).run();

    // 8. Enviar cookie de sessão e redirecionar para a página principal
    const sessionCookie = `Host-session=\({sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=\){60 * 60 * 24 * 7}`;
    const clearTxCookie = `Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

    return new Response(null, {
        status: 302,
        headers: new Headers([
            ['Location', '/'],
            ['Set-Cookie', sessionCookie],
            ['Set-Cookie', clearTxCookie] // Apaga o cookie temporário
        ])
    });
}
