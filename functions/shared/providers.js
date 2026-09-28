// functions/shared/providers.js

export async function validateGithubUser(accessToken, clientId, clientSecret) {
    // 9. Chamar a API do GitHub para obter o perfil do utilizador (Etapa 13.5)
    const userRes = await fetch("https://api.github.com/user", {
        headers: {
            "Authorization": `Bearer ${accessToken}`,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "Laboratorio-Autenticacao" 
        }
    });

    if (!userRes.ok) throw new Error("Falha ao obter perfil do GitHub");
    const user = await userRes.json();

    // 10. Revogar a autorização da OAuth App imediatamente (Etapa 13.5)
    // Usamos autenticação Basic (ClientId:ClientSecret)
    const basicAuth = btoa(`\({clientId}:\){clientSecret}`);
    const revokeRes = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
        method: "DELETE",
        headers: {
            "Authorization": `Basic ${basicAuth}`,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
            "User-Agent": "Laboratorio-Autenticacao"
        },
        body: JSON.stringify({ access_token: accessToken })
    });

    if (revokeRes.status !== 204) throw new Error("Falha ao revogar token no GitHub");

    // Retorna a identidade normalizada
    return {
        issuer: "https://github.com",
        subject: String(user.id), // id numérico convertido em texto, como pede o guião
        email: user.email || null,
        name: user.name || user.login
    };
}
