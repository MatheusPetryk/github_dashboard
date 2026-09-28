import { calculateHash, generateRandomString } from "../../shared/crypto.js";

export async function onRequestGet(context) {
    const provider = context.params.provider;
    const requestUrl = new URL(context.request.url);
    
    const code = requestUrl.searchParams.get("code");
    const state = requestUrl.searchParams.get("state");
    const error = requestUrl.searchParams.get("error");

    // 1. Recusar error ou a ausência de code e state (Etapa 13.4)
    if (error || !code || !state) {
        return new Response("Faltam parâmetros ou provedor retornou erro.", { 
            status: 400, 
            headers: { "Cache-Control": "no-store" } 
        });
    }

    // 2. Exigir o cookie temporário Host-oauth-tx
    const cookieHeader = context.request.headers.get("Cookie") || "";
    const txCookieMatch = cookieHeader.match(/(?:^|;\s*)__Host-oauth-tx=([^;]+)/) || cookieHeader.match(/(?:^|;\s*)Host-oauth-tx=([^;]+)/);
    
    if (!txCookieMatch) {
        return new Response("Cookie de transação ausente.", { 
            status: 400, 
            headers: { "Cache-Control": "no-store" } 
        });
    }
    const txCookie = txCookieMatch[1];

    // 3. Calcular o resumo (hash) do cookie e localizar transação não expirada no D1
    const idHash = await calculateHash(txCookie);
    const db = context.env.DB;

    const tx = await db.prepare(
        `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ?`
    ).bind(idHash, provider).first();

    const now = Math.floor(Date.now() / 1000);

    // Se não existir transação ou estiver expirada
    if (!tx || now > tx.expires_at) {
        if (tx) { // Se expirou, limpamos o lixo
            await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();
        }
        return new Response("Transação ausente ou expirada.", { 
            status: 400, 
            headers: { "Cache-Control": "no-store" } 
        });
    }

    // 4. Comparar o resumo de state com o valor conservado no D1
    const stateHash = await calculateHash(state);
    if (stateHash !== tx.state_hash) {
        await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();
        return new Response("State inválido. Possível ataque CSRF.", { 
            status: 400, 
            headers: { "Cache-Control": "no-store" } 
        });
    }

    // 5. Apagar a transação ANTES de concluir o fluxo (evita ataques de repetição)
    await db.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(idHash).run();


    // --- AQUI VAI ENTRAR O PASSO 6 e 7: A TROCA DO CÓDIGO PELO TOKEN ---
    // (Vamos fazer isso no próximo passo, por agora vamos apenas avisar que deu certo)

    return new Response(`Transação validada com sucesso para o provedor: ${provider}. Falta trocar o código pelo token!`, { 
        status: 200,
        headers: { "Cache-Control": "no-store" }
    });
}
