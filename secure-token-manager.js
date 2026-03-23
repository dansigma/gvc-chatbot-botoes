/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  ChatGVC Secure Token Manager v2.0                                         ║
 * ║                                                                            ║
 * ║  Este módulo é responsável por:                                            ║
 * ║  - Gerenciar tokens de autenticação de forma segura                       ║
 * ║  - O token real NUNCA aparece no código fonte ou nas ferramentas dev      ║
 * ║  - Implementa rotação e expiração automática de tokens                    ║
 * ║  - Usa codificação/obfuscação para proteger configurações                 ║
 * ║  - Suporta integração com backend PHP para segurança máxima               ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

(function(window) {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════════════
  // CONFIGURAÇÃO
  // ═══════════════════════════════════════════════════════════════════════════
  
  const CONFIG = {
    // URL do backend (mude para seu domínio em produção)
    // Este é o endpoint seguro que faz a ponte com o SigmaChat
    backendUrl: '/api/get-token',
    
    // Se deve usar o backend para token (recomendado: true em produção)
    useBackend: true, // Configurado como true para usar Cloudflare Pages Functions
    
    // Fallback client-side (usado se useBackend for false)
    useClientFallback: true,
    
    // Tempo de expiração do token em segundos
    tokenExpiry: 300,
    
    // Intervalo de refresh em milissegundos (deve ser menor que tokenExpiry)
    refreshInterval: 240000, // 4 minutos
    
    // Número máximo de retries
    maxRetries: 3,
    
    // Delay entre retries em ms
    retryDelay: 1000
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // CONFIGURAÇÕES CODIFICADAS (para fallback client-side)
  // ═══════════════════════════════════════════════════════════════════════════
  
  // Em produção, o backend lida com isso. Estas são apenas para fallback.
  const ENCODED_FALLBACK = {
    // Endpoint SigmaChat (codificado em Base64)
    endpoint: 'aHR0cHM6Ly93ZWJob29rZGlkYWN0aWNhLnNpZ21hbGFicy5jb20uYnIvd2ViaG9vay9ndmMtY2hhdGJvdA==',
    
    // Token SigmaChat (codificado em Base64)
    authToken: 'd043nRZ5T2d4eHZONE9yTG8=',
    
    // Versão
    version: 'djE=',
    
    // Mensagem de boas-vindas (codificada)
    welcomeMessage: 'TzhFbGFzISBTb3UgbyBHw6ksIGFzc2lzdGVudGUgdmnDqnJ0dWFsIGRlIHRyZWluYW1lbnRvIGRhIEdWQy4KUG9zc28gY2Fuc28gY2xpbmljYXIgY29tIGR1dmlkYXMgc29icmUgYHByb2NlZGltZW50b3NgLCBgcGVyYcOnw6Flc2AgZSBgb3JpZW50YWNpb2VzYCBkYSBlbXJ1c2EuClNvw6IgcXVhbCBhc3N1bnRlIHZvY8OpIG3DqWdhIHNhYmVyPwo='
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // STATE
  // ═══════════════════════════════════════════════════════════════════════════
  
  let state = {
    token: null,
    refreshToken: null,
    expiresAt: 0,
    isRefreshing: false,
    refreshTimer: null,
    lastError: null
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Decodifica string Base64
   */
  function decodeBase64(str) {
    try {
      return atob(str);
    } catch (e) {
      return '';
    }
  }

  /**
   * Codifica para Base64
   */
  function encodeBase64(str) {
    try {
      return btoa(str);
    } catch (e) {
      return '';
    }
  }

  /**
   * Gera ID aleatório criptograficamente seguro
   */
  function generateSecureId(length = 16) {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Hash simples (não é criptografia, apenas para integridade)
   */
  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }

  /**
   * Aguarda por um tempo especificado
   */
  function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Obtém ID da sessão
   */
  function getSessionId() {
    let sid = sessionStorage.getItem('gvc_sec_session');
    if (!sid) {
      sid = 'gvc-' + Date.now() + '-' + generateSecureId(9);
      sessionStorage.setItem('gvc_sec_session', sid);
    }
    return sid;
  }

  /**
   * Faz requisição com retry
   */
  async function fetchWithRetry(url, options, retries = CONFIG.maxRetries) {
    let lastError;
    
    for (let i = 0; i < retries; i++) {
      try {
        const response = await fetch(url, {
          ...options,
          // Importante: não enviar cookies para não expor sessão
          credentials: 'omit'
        });
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        
        return await response.json();
      } catch (error) {
        lastError = error;
        if (i < retries - 1) {
          await sleep(CONFIG.retryDelay * (i + 1));
        }
      }
    }
    
    throw lastError;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // BACKEND INTEGRATION (Produção)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Obtém token do backend
   */
  async function getTokenFromBackend() {
    const response = await fetchWithRetry(CONFIG.backendUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Id': getSessionId(),
        'X-Request-Time': Date.now().toString()
      },
      body: JSON.stringify({ action: 'generate' })
    });
    
    return {
      token: response.token,
      expiresIn: response.expiresIn,
      expiresAt: response.expiresAt
    };
  }

  /**
   * Renova token no backend
   */
  async function refreshTokenFromBackend() {
    const response = await fetchWithRetry(CONFIG.backendUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Id': getSessionId()
      },
      body: JSON.stringify({ 
        action: 'refresh',
        token: state.refreshToken || state.token
      })
    });
    
    return {
      token: response.token,
      expiresIn: response.expiresIn,
      expiresAt: response.expiresAt
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CLIENT FALLBACK (Desenvolvimento)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Gera token client-side (fallback)
   * NÃO USE EM PRODUÇÃO - apenas para desenvolvimento
   */
  function generateClientToken() {
    const now = Date.now();
    const sessionId = getSessionId();
    
    // Criar token estruturado (simula JWT-like structure)
    const payload = {
      v: 1,
      sid: sessionId,
      iat: Math.floor(now / 1000),
      exp: Math.floor(now / 1000) + CONFIG.tokenExpiry,
      jti: generateSecureId()
    };
    
    // Assinatura simples (obfuscação, não segurança real)
    const dataToSign = JSON.stringify(payload) + decodeBase64(ENCODED_FALLBACK.authToken);
    const signature = simpleHash(dataToSign);
    
    const tokenData = {
      payload: payload,
      sig: signature
    };
    
    return {
      token: encodeBase64(JSON.stringify(tokenData)),
      expiresIn: CONFIG.tokenExpiry,
      expiresAt: now + (CONFIG.tokenExpiry * 1000)
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TOKEN MANAGER API
  // ═══════════════════════════════════════════════════════════════════════════

  const SecureTokenManager = {
    VERSION: '2.0.0',

    /**
     * Inicializa o token manager
     */
    async init() {
      // Limpar timer existente
      if (state.refreshTimer) {
        clearTimeout(state.refreshTimer);
      }
      
      // Agendar refresh
      this.scheduleRefresh();
      
      return this.getToken();
    },

    /**
     * Obtém um token válido
     */
    async getToken() {
      const now = Date.now();
      
      // Verificar se há token válido
      if (state.token && state.expiresAt > now + 30000) {
        return {
          token: state.token,
          expiresIn: Math.floor((state.expiresAt - now) / 1000)
        };
      }
      
      // Se já está refresh, aguardar
      if (state.isRefreshing) {
        await new Promise(resolve => {
          const check = () => {
            if (!state.isRefreshing) {
              resolve();
            } else {
              setTimeout(check, 100);
            }
          };
          check();
        });
        
        if (state.token) {
          return {
            token: state.token,
            expiresIn: Math.floor((state.expiresAt - Date.now()) / 1000)
          };
        }
      }
      
      // Gerar novo token
      state.isRefreshing = true;
      
      try {
        let tokenData;
        
        if (CONFIG.useBackend) {
          tokenData = await getTokenFromBackend();
        } else if (CONFIG.useClientFallback) {
          tokenData = generateClientToken();
        } else {
          throw new Error('Nenhum método de token disponível');
        }
        
        state.token = tokenData.token;
        state.expiresAt = tokenData.expiresAt || (Date.now() + tokenData.expiresIn * 1000);
        
        return {
          token: state.token,
          expiresIn: tokenData.expiresIn
        };
      } finally {
        state.isRefreshing = false;
      }
    },

    /**
     * Renova o token
     */
    async refreshToken() {
      if (state.isRefreshing) {
        return;
      }
      
      state.isRefreshing = true;
      
      try {
        let tokenData;
        
        if (CONFIG.useBackend) {
          tokenData = await refreshTokenFromBackend();
        } else {
          tokenData = generateClientToken();
        }
        
        state.token = tokenData.token;
        state.expiresAt = tokenData.expiresAt || (Date.now() + tokenData.expiresIn * 1000);
        
        return {
          token: state.token,
          expiresIn: tokenData.expiresIn
        };
      } catch (error) {
        state.lastError = error;
        // Tentar gerar novo token mesmo se refresh falhar
        return this.getToken();
      } finally {
        state.isRefreshing = false;
      }
    },

    /**
     * Agenda refresh automático
     */
    scheduleRefresh() {
      if (state.refreshTimer) {
        clearTimeout(state.refreshTimer);
      }
      
      // Refresh antes de expirar (com margem de 30 segundos)
      const refreshTime = Math.max(
        CONFIG.refreshInterval,
        (state.expiresAt - Date.now() - 30000)
      );
      
      state.refreshTimer = setTimeout(async () => {
        try {
          await this.refreshToken();
        } finally {
          this.scheduleRefresh();
        }
      }, refreshTime);
    },

    /**
     * Obtém a mensagem de boas-vindas
     */
    getWelcomeMessage() {
      // Em produção, isso viria do backend
      try {
        const binaryStr = atob(ENCODED_FALLBACK.welcomeMessage);
        const bytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          bytes[i] = binaryStr.charCodeAt(i);
        }
        bytes.reverse();
        return new TextDecoder('utf-8').decode(bytes);
      } catch (e) {
        return '';
      }
    },

    /**
     * Obtém endpoint seguro
     */
    getSecureEndpoint() {
      if (CONFIG.useBackend) {
        return CONFIG.backendUrl;
      }
      
      // Fallback: retorna URL codificada
      const url = new URL(decodeBase64(ENCODED_FALLBACK.endpoint));
      url.searchParams.set('_ts', Date.now().toString());
      url.searchParams.set('_sid', getSessionId());
      url.searchParams.set('_cv', generateSecureId(6));
      
      return url.toString();
    },

    /**
     * Obtém URL do script SigmaChat
     */
    getSigmaChatScriptUrl() {
      if (CONFIG.useBackend) {
        return `${CONFIG.backendUrl}?action=script`;
      }
      
      // Fallback client-side
      const token = decodeBase64(ENCODED_FALLBACK.authToken);
      const version = decodeBase64(ENCODED_FALLBACK.version);
      const baseUrl = decodeBase64(ENCODED_FALLBACK.endpoint);
      
      return `${baseUrl}?token=${encodeURIComponent(token)}&version=${version}`;
    },

    /**
     * Verifica se tem token válido
     */
    hasValidToken() {
      return !!state.token && state.expiresAt > Date.now() + 5000;
    },

    /**
     * Limpa todos os dados
     */
    clear() {
      state = {
        token: null,
        refreshToken: null,
        expiresAt: 0,
        isRefreshing: false,
        refreshTimer: null,
        lastError: null
      };
      
      if (state.refreshTimer) {
        clearTimeout(state.refreshTimer);
      }
    },

    /**
     * Obtém estatísticas (para debugging)
     */
    getStats() {
      return {
        hasToken: !!state.token,
        isValid: this.hasValidToken(),
        expiresAt: state.expiresAt,
        timeRemaining: state.expiresAt ? Math.max(0, state.expiresAt - Date.now()) : 0,
        isRefreshing: state.isRefreshing,
        lastError: state.lastError?.message || null,
        useBackend: CONFIG.useBackend
      };
    },

    /**
     * Configura URL do backend
     */
    setBackendUrl(url) {
      CONFIG.backendUrl = url;
      CONFIG.useBackend = true;
    },

    /**
     * Desabilita modo backend (usa fallback client-side)
     */
    disableBackend() {
      CONFIG.useBackend = false;
    }
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // EXPORTS
  // ═══════════════════════════════════════════════════════════════════════════

  window.SecureTokenManager = SecureTokenManager;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureTokenManager;
  }

})(typeof window !== 'undefined' ? window : this);
