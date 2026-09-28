const API_VERSION = "2026-03-10";
 
export async function validateGithubUser(accessToken, clientId, clientSecret) {
  // 10. Consultar o perfil
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": API_VERSION,
      "User-Agent": "oauth-pages-lab",
    },
  });
  if (userRes.status !== 200) throw new Error("github_user");
 
  const user = await userRes.json();
  if (!Number.isInteger(user.id)) throw new Error("github_id");
 
  // Revogar a autorizacao (exige 204 antes de criar a sessao)
  const basic = btoa(`${clientId}:${clientSecret}`);
  const revokeRes = await fetch(`https://api.github.com/applications/${clientId}/grant`, {
    method: "DELETE",
    headers: {
      Authorization: `Basic ${basic}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "X-GitHub-Api-Version": API_VERSION,
      "User-Agent": "oauth-pages-lab",
    },
    body: JSON.stringify({ access_token: accessToken }),
  });
  if (revokeRes.status !== 204) throw new Error("github_revoke");
 
  return {
    issuer: "https://github.com",
    subject: String(user.id),
    email: user.email ?? null,
    name: user.name || user.login || null,
  };
}
