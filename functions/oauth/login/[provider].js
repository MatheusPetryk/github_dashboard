// 5. Configurar a URL de redirecionamento para o provedor escolhido
    const clientId = context.env[`${provider.toUpperCase()}_CLIENT_ID`];
    const redirectUri = `\({context.env.PUBLIC_BASE_URL}/oauth/callback/\){provider}`;
    
    let authUrl = new URL(provider === 'google' 
        ? 'https://accounts.google.com/o/oauth2/v2/auth' 
        : 'https://github.com/login/oauth/authorize');

    // Parâmetros essenciais limpos
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
