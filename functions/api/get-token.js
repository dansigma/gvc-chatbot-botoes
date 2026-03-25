/**
 * Cloudflare Pages Function for Secure Token & Proxy Endpoint
 * Atua como backend de segurança e proxy reverso para o webhook n8n
 */

const DEFAULT_TOKEN_EXPIRY = 300; // 5 minutos em segundos

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

async function verifyToken(token, envConfig) {
  try {
    const decoded = atob(token);
    const tokenData = JSON.parse(decoded);

    if (!tokenData || !tokenData.payload) {
      return { valid: false, reason: 'malformed' };
    }

    // Verificar expiração
    const now = Math.floor(Date.now() / 1000);
    if (tokenData.payload.exp < now) {
      return { valid: false, reason: 'expired' };
    }

    // Verificar assinatura HMAC
    const dataToSign = JSON.stringify(tokenData.payload) + envConfig.SIGMACHAT_TOKEN;
    const expectedSignature = await hmacSha256(dataToSign, envConfig.BACKEND_AUTH_TOKEN);

    if (expectedSignature !== tokenData.signature) {
      return { valid: false, reason: 'invalid_signature' };
    }

    return { valid: true, payload: tokenData.payload };
  } catch (e) {
    return { valid: false, reason: 'corrupt' };
  }
}

async function refreshToken(oldToken, envConfig) {
  const verification = await verifyToken(oldToken, envConfig);
  if (!verification.valid) return null;
  return await generateSecureToken(verification.payload.sid, envConfig);
}

function returnError(message, status = 400, corsHeaders = {}) {
  return new Response(JSON.stringify({ error: true, message }), {
    status,
    headers: { ...corsHeaders, 'Content-Type': 'application/json' }
  });
}

export async function onRequest(context) {
  const { request, env } = context;

  // Montando a configuração final a partir do env (sem fallback para secrets)
  const envConfig = {
    SIGMACHAT_TOKEN: env.SIGMACHAT_TOKEN,
    SIGMACHAT_BASE_URL: env.SIGMACHAT_BASE_URL,
    BACKEND_AUTH_TOKEN: env.BACKEND_AUTH_TOKEN,
    TOKEN_EXPIRY: env.TOKEN_EXPIRY || DEFAULT_TOKEN_EXPIRY
  };

  // Validar que todas as variáveis obrigatórias estão configuradas
  if (!envConfig.SIGMACHAT_TOKEN || !envConfig.SIGMACHAT_BASE_URL || !envConfig.BACKEND_AUTH_TOKEN) {
    return returnError('Server configuration incomplete', 500, {});
  }

  // Verificando e permitindo CORS com allowlist
  const allowedOriginsRaw = env.ALLOWED_ORIGINS || '';
  const allowedOrigins = allowedOriginsRaw.split(',').map(o => o.trim()).filter(Boolean);
  const requestOrigin = request.headers.get('Origin') || '';

  // Se ALLOWED_ORIGINS está configurado, validar origem
  if (allowedOrigins.length > 0 && requestOrigin && !allowedOrigins.includes(requestOrigin)) {
    return new Response(JSON.stringify({ error: true, message: 'Origin not allowed' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const corsHeaders = {
    'Access-Control-Allow-Origin': requestOrigin || (allowedOrigins.length > 0 ? allowedOrigins[0] : '*'),
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
        // 1. Validar token de segurança (expiração + assinatura HMAC)
        let token = request.headers.get('X-Secure-Token') || body.token || '';
        const verification = await verifyToken(token, envConfig);

        if (!verification.valid) {
          const msg = verification.reason === 'expired'
            ? 'Sessão expirada. Recarregue a página.'
            : 'Acesso não autorizado.';
          return returnError(msg, 401, responseHeaders);
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
                 sessionId: sessionId,
                 button: body.button || false
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

      case 'validate': {
        let token = body.token || request.headers.get('Authorization') || '';
        token = token.replace('Bearer ', '');

        const validationResult = await verifyToken(token, envConfig);

        if (validationResult.valid) {
          const now = Math.floor(Date.now() / 1000);
          return new Response(JSON.stringify({
            valid: true,
            expiresAt: validationResult.payload.exp,
            timeRemaining: Math.max(0, validationResult.payload.exp - now)
          }), { headers: responseHeaders });
        } else {
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
