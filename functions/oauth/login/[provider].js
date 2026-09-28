import { generateRandomString, calculateHash } from "../../shared/crypto.js";

export async function onRequestGet(context) {
    const provider = context.params.provider;

    if (provider !== 'google' && provider !== 'github') {
        return new Response("Not Found", { status: 404 });
    }

    const transactionId = generateRandomString();
    const state = generateRandomString();
    const codeVerifier = generateRandomString();
    const nonce = provider === 'google' ? generateRandomString() : null;

    const idHash = await calculateHash(transactionId);
    const stateHash = await calculateHash(state);
    const codeChallenge = await calculateHash(codeVerifier);
    const expiresAt = Math.floor(Date.now() / 1000) + 600;

    await context.env.DB.prepare(
        `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(idHash, provider, stateHash, nonce, codeVerifier, expiresAt).run();

    const clientId = context.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const redirectUri = `\({context.env.PUBLIC_BASE_URL}/oauth/callback/\){provider}`;
    
    let authUrl = new URL(provider === 'google' 
        ? 'https://accounts.google.com/o/oauth2/v2/auth' 
        : 'https://github.com/login/oauth/authorize');

    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('state', state);

    if (provider === 'google') {
        authUrl.searchParams.set('scope', 'openid email profile');
        authUrl.searchParams.set('nonce', nonce);
        authUrl.searchParams.set('code_challenge', codeChallenge);
        authUrl.searchParams.set('code_challenge_method', 'S256');
    }

    const cookie = `Host-oauth-tx=${transactionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

    return new Response(null, {
        status: 302,
        headers: {
            'Location': authUrl.toString(),
            'Set-Cookie': cookie
        }
    });
}
