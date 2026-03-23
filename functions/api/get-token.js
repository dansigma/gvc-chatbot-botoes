/**
 * Cloudflare Pages Function for Secure Token & Proxy Endpoint
 * Atua como backend de segurança e proxy reverso para o webhook n8n
 */

const DEFAULT_CONFIG = {
  SIGMACHAT_TOKEN: 'wN7tZgOlxvN9OrLo',
  SIGMACHAT_BASE_URL: 'https://webhookdidactica.sigmalabs.com.br/webhook/gvc-chatbot',
  BACKEND_AUTH_TOKEN: 'sua-chave-secreta-backend-mude-isso',
  TOKEN_EXPIRY: 300 // 5 minutos em segundos
};

// Funções criptográficas auxiliares (Web Crypto API)
async function hmacSha256(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign('HMAC', key, enc.encode(data));
  const hexSignature = Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return hexSignature;
}

function generateSecureId(length = 16) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

async function generateSecureToken(sessionId, envConfig) {
  const now = Math.floor(Date.now() / 1000);
  const expiry = now + (parseInt(envConfig.TOKEN_EXPIRY) || 300);
  
  const payload = {
    sid: sessionId,
    exp: expiry,
    iat: now,
    jti: generateSecureId(8)
  };

  const dataToSign = JSON.stringify(payload) + envConfig.SIGMACHAT_TOKEN;
  const signature = await hmacSha256(dataToSign, envConfig.BACKEND_AUTH_TOKEN);

  const tokenData = {
    payload: payload,
    signature: signature
  };

  return {
    token: btoa(JSON.stringify(tokenData)),
    expiresIn: parseInt(envConfig.TOKEN_EXPIRY) || 300,
    expiresAt: expiry * 1000 // retorno em ms para o cliente
  };
}

async function refreshToken(oldToken, envConfig) {
  try {
    const decoded = atob(oldToken);
    const tokenData = JSON.parse(decoded);
    
    if (!tokenData || !tokenData.payload) return null;

    const dataToSign = JSON.stringify(tokenData.payload) + envConfig.SIGMACHAT_TOKEN;
    const expectedSignature = await hmacSha256(dataToSign, envConfig.BACKEND_AUTH_TOKEN);

    if (expectedSignature !== tokenData.signature) {
      return null;
    }

    return await generateSecureToken(tokenData.payload.sid, envConfig);
  } catch (e) {
    return null;
  }
}

function returnError(message, status = 400, corsHeaders = {}) {
  return new Response(JSON.stringify({ error: true, message }), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

export async function onRequest(context) {
  const { request, env } = context;

  // Montando a configuração final a partir do env ou valores default
  const envConfig = {
    SIGMACHAT_TOKEN: env.SIGMACHAT_TOKEN || DEFAULT_CONFIG.SIGMACHAT_TOKEN,
    SIGMACHAT_BASE_URL: env.SIGMACHAT_BASE_URL || DEFAULT_CONFIG.SIGMACHAT_BASE_URL,
    BACKEND_AUTH_TOKEN: env.BACKEND_AUTH_TOKEN || DEFAULT_CONFIG.BACKEND_AUTH_TOKEN,
    TOKEN_EXPIRY: env.TOKEN_EXPIRY || DEFAULT_CONFIG.TOKEN_EXPIRY
  };

  // Verificando e permitindo CORS
  const origin = request.headers.get('Origin') || '*';
  const corsHeaders = {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Session-Id, X-Request-Time, X-Secure-Token',
    'Access-Control-Max-Age': '86400',
  };

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  if (request.method !== 'POST' && request.method !== 'GET') {
    return returnError('Método não permitido', 405, corsHeaders);
  }

  // Parse corpo da requisição e URL params
  let action = 'generate';
  let body = {};
  
  if (request.method === 'POST') {
    try {
      body = await request.json();
      action = body.action || action;
    } catch (e) {
      // Body vazio ou mal formado, continua
    }
  }
  
  const url = new URL(request.url);
  if (url.searchParams.has('action')) {
    action = url.searchParams.get('action');
  }

  // Se 'chatInput' foi enviado no body, interceptamos como uma ação de proxy_chat!
  if (body.chatInput) {
    action = 'proxy_chat';
  }

  const sessionId = request.headers.get('X-Session-Id') || body.sessionId || generateSecureId(10);

  // Headers de resposta de segurança
  const responseHeaders = {
    ...corsHeaders,
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff'
  };

  try {
    switch (action) {
      
      // ==========================================================
      // AÇÃO INJETADA PARA PROXY (n8n WEBHOOK)
      // ==========================================================
      case 'proxy_chat': {
        // 1. Validar se o requesitante tem um token de segurança gerado por nós (e não expirado)
        let token = request.headers.get('X-Secure-Token') || body.token || '';
        try {
          const decoded = atob(token);
          const tokenData = JSON.parse(decoded);
          const now = Math.floor(Date.now() / 1000);
          
          if (!tokenData || !tokenData.payload || tokenData.payload.exp < now) {
            return returnError('Sessão expirada. Recarregue a página.', 401, responseHeaders);
          }
        } catch(e) {
          return returnError('Acesso bloqueado. Solicitação corrompida.', 401, responseHeaders);
        }

        // 2. Se tudo estiver seguro, enviamos a mensagem para o verdadeiro n8n Webhook
        try {
           const proxyResponse = await fetch(envConfig.SIGMACHAT_BASE_URL, {
              method: 'POST',
              headers: {
                 'Content-Type': 'application/json'
                 // Se o seu n8n necessitar de Bearer, decomente a linha abaixo
                 // 'Authorization': `Bearer ${envConfig.SIGMACHAT_TOKEN}`
              },
              body: JSON.stringify({
                 chatInput: body.chatInput,
                 sessionId: sessionId
              })
           });
           
           const data = await proxyResponse.text();
           return new Response(data, {
               status: proxyResponse.status,
               headers: responseHeaders
           });
        } catch(e) {
           return returnError('Serviço indisponível no momento.', 502, responseHeaders);
        }
      }

      // ==========================================================
      // AÇÕES ORIGINAIS DE SEGURANÇA E MANIPULAÇÃO DE TOKENS
      // ==========================================================
      case 'generate': {
        const tokenInfo = await generateSecureToken(sessionId, envConfig);
        return new Response(JSON.stringify(tokenInfo), { headers: responseHeaders });
      }

      case 'refresh': {
        let oldToken = body.token || request.headers.get('Authorization') || '';
        oldToken = oldToken.replace('Bearer ', '');

        const newTokenInfo = await refreshToken(oldToken, envConfig);
        if (newTokenInfo) {
          return new Response(JSON.stringify(newTokenInfo), { headers: responseHeaders });
        } else {
          const freshTokenInfo = await generateSecureToken(sessionId, envConfig);
          return new Response(JSON.stringify(freshTokenInfo), { headers: responseHeaders });
        }
      }

      case 'script': {
        // Rota apenas de legacy/referência
        const scriptUrl = `${envConfig.SIGMACHAT_BASE_URL}?token=${encodeURIComponent(envConfig.SIGMACHAT_TOKEN)}&version=v1`;
        return new Response(JSON.stringify({ scriptUrl }), { headers: responseHeaders });
      }

      case 'validate': {
        let token = body.token || request.headers.get('Authorization') || '';
        token = token.replace('Bearer ', '');
        
        try {
          const decoded = atob(token);
          const tokenData = JSON.parse(decoded);
          const now = Math.floor(Date.now() / 1000);

          if (tokenData && tokenData.payload && tokenData.payload.exp) {
            const isValid = tokenData.payload.exp > now;
            return new Response(JSON.stringify({
              valid: isValid,
              expiresAt: tokenData.payload.exp,
              timeRemaining: Math.max(0, tokenData.payload.exp - now)
            }), { headers: responseHeaders });
          } else {
            return new Response(JSON.stringify({ valid: false }), { headers: responseHeaders });
          }
        } catch(e) {
          return new Response(JSON.stringify({ valid: false }), { headers: responseHeaders });
        }
      }

      default:
        return returnError('Ação inválida/não mapeada', 400, responseHeaders);
    }
  } catch (error) {
    return returnError('Erro Crítico no Servidor', 500, responseHeaders);
  }
}
