/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  ChatGVC Secure Token Manager v2.0                                         ║
 * ║                                                                            ║
 * ║  Este módulo é responsável por:                                            ║
 * ║  - Gerenciar tokens de autenticação de forma segura                       ║
 * ║  - O token real NUNCA aparece no código fonte ou nas ferramentas dev      ║
 * ║  - Implementa rotação e expiração automática de tokens                    ║
 * ║  - Integração com backend Cloudflare Pages Functions                      ║
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

    // Deve usar o backend para token (obrigatório em produção)
    useBackend: true,

    // Fallback client-side (desativado — backend é obrigatório)
    useClientFallback: false,

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
  // DADOS ESTÁTICOS (não-sensíveis)
  // ═══════════════════════════════════════════════════════════════════════════

  // Mensagem de boas-vindas codificada em UTF-8/Base64
  const ENCODED_FALLBACK = {
    welcomeMessage: '8J+RiyBPbMOhISBUZW0gYWxndW1hIGTDunZpZGEgc29icmUgcHJvY2VkaW1lbnRvcyBvdSBvcGVyYcOnw7VlcyBkYSBHVkM/IFBvZGUgcGVyZ3VudGFyIMOgIHZvbnRhZGUh'
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
        } else {
          throw new Error('Backend é obrigatório para geração de token');
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
          throw new Error('Backend é obrigatório para refresh de token');
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
        return new TextDecoder('utf-8').decode(bytes);
      } catch (e) {
        return '';
      }
    },

    /**
     * Obtém endpoint seguro
     */
    getSecureEndpoint() {
      return CONFIG.backendUrl;
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
      const oldTimer = state.refreshTimer;
      state = {
        token: null,
        refreshToken: null,
        expiresAt: 0,
        isRefreshing: false,
        refreshTimer: null,
        lastError: null
      };
      if (oldTimer) {
        clearTimeout(oldTimer);
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

  };

  // ═══════════════════════════════════════════════════════════════════════════
  // EXPORTS
  // ═══════════════════════════════════════════════════════════════════════════

  window.SecureTokenManager = SecureTokenManager;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureTokenManager;
  }

})(typeof window !== 'undefined' ? window : this);
