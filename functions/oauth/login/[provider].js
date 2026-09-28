import { generateRandomString, calculateHash } from "../../shared/crypto.js";

export async function onRequestGet(context) {
    const provider = context.params.provider;

    // 1. Aceitar apenas google ou github (Etapa 13.3)
    if (provider !== 'google' && provider !== 'github') {
        return new Response("Not Found", { status: 404 });
    }

    // 2. Gerar valores aleatórios (PKCE e proteção CSRF)
    const transactionId = generateRandomString();
    const state = generateRandomString();
    const codeVerifier = generateRandomString();
    // O nonce é exclusivo para o Google (OIDC)
    const nonce = provider === 'google' ? generateRandomString() : null;

    // 3. Calcular os hashes para guardar na base de dados
    const idHash = await calculateHash(transactionId);
    const stateHash = await calculateHash(state);
    
    // O code_challenge é derivado do code_verifier usando SHA-256
    const codeChallenge = await calculateHash(codeVerifier);

    // Definir expiração para 10 minutos (600 segundos) a partir de agora
    const expiresAt = Math.floor(Date.now() / 1000) + 600;

    // 4. Gravar a transação no D1 (Etapa 13.3)
    await context.env.DB.prepare(
        `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

    // 5. Configurar a URL de redirecionamento para o provedor escolhido
    const clientId = context.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const redirectUri = `\({context.env.PUBLIC_BASE_URL}/oauth/callback/\){provider}`;
    
    let authUrl = new URL(provider === 'google' 
        ? 'https://accounts.google.com/o/oauth2/v2/auth' 
        : 'https://github.com/login/oauth/authorize');

    // Parâmetros comuns aos dois provedores
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', state);
    
    // Parâmetros PKCE (apenas suportado oficialmente aqui pelo Google, mas o roteiro pede para ambos)
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    // Parâmetros específicos do Google
    if (provider === 'google') {
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('nonce', nonce);
    }

    // 6. Criar o cookie temporário e responder com o redirecionamento (302)
    const cookie = `Host-oauth-tx=${transactionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

    return new Response(null, {
        status: 302,
        headers: {
            'Location': authUrl.toString(),
            'Set-Cookie': cookie
        }
    });
}
