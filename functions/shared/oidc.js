// functions/shared/oidc.js

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) { str += '='; }
    return atob(str);
}

export async function validateGoogleToken(idToken, clientId, expectedNonce) {
    // 1. Separar as três partes do JWT (Cabeçalho, Carga Útil, Assinatura) (Etapa 13.5)
    const parts = idToken.split('.');
    if (parts.length !== 3) throw new Error("JWT inválido");

    const headerStr = base64UrlDecode(parts[0]);
    const payloadStr = base64UrlDecode(parts[1]);
    const signatureStr = parts[2];

    const header = JSON.parse(headerStr);
    const payload = JSON.parse(payloadStr);

    // 2. Exigir alg igual a RS256
    if (header.alg !== 'RS256') throw new Error("Algoritmo não suportado");

    // 3 e 4. Obter o documento de descoberta OIDC e o conjunto de chaves (JWKS)
    const discoveryRes = await fetch("https://accounts.google.com/.well-known/openid-configuration");
    const discovery = await discoveryRes.json();
    
    const jwksRes = await fetch(discovery.jwks_uri);
    const jwks = await jwksRes.json();

    // 5. Selecionar a chave pública correta pelo 'kid' (Key ID)
    const jwk = jwks.keys.find(k => k.kid === header.kid);
    if (!jwk) throw new Error("Chave não encontrada");

    // 6. Importar a JWK para a Web Crypto API
    const key = await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["verify"]
    );

    // 7. Verificar a assinatura matemática do JWT
    const encoder = new TextEncoder();
    const data = encoder.encode(parts[0] + "." + parts[1]);
    
    // Converter a assinatura base64url para Uint8Array
    const sigBase64 = signatureStr.replace(/-/g, '+').replace(/_/g, '/');
    const sigString = atob(sigBase64);
    const sigBytes = new Uint8Array(sigString.length);
    for (let i = 0; i < sigString.length; i++) {
        sigBytes[i] = sigString.charCodeAt(i);
    }

    const isValid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sigBytes, data);
    if (!isValid) throw new Error("Assinatura do JWT inválida");

    // 8. Validar iss, aud, exp e nonce de segurança
    const now = Math.floor(Date.now() / 1000);
    if (payload.iss !== "https://accounts.google.com" && payload.iss !== "accounts.google.com") {
        throw new Error("Emissor inválido");
    }
    if (payload.aud !== clientId) throw new Error("Audiência inválida");
    if (now > payload.exp) throw new Error("Token expirado");
    if (payload.nonce !== expectedNonce) throw new Error("Nonce inválido");

    // Se chegou até aqui, a identidade é 100% autêntica e validada!
    return {
        issuer: "https://accounts.google.com",
        subject: payload.sub,
        email: payload.email,
        name: payload.name
    };
}
