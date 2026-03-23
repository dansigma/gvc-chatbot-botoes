# ChatGVC Secure Wrapper

## Visão Geral

Esta solução fornece uma camada de segurança para o chatbot GVC, ocultando completamente:
- Endpoint do SigmaChat
- Token de autenticação
- URLs de arquivos hospedados
- Dados de configuração sensíveis

## Arquitetura

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│   Cliente       │      │  Secure Wrapper  │      │    Backend      │
│   (Navegador)  │─────▶│  (chatgvc-       │─────▶│  (get-token.php)│
│                 │      │   secure-wrapper)│      │                 │
└─────────────────┘      └──────────────────┘      └─────────────────┘
                               │                         │
                               │   getToken()             │
                               │   getSecureEndpoint()    │
                               │◀── retorna token ───────│
                               │        (obfuscado)       │
                               │                         │
                               ▼                         ▼
                        ┌──────────────────┐      ┌─────────────────┐
                        │ SigmaChat Script │      │    SigmaChat    │
                        │  (carregado via  │─────▶│    Service      │
                        │   URL segura)    │      │                 │
                        └──────────────────┘      └─────────────────┘
```

## Arquivos

### Core
- `chatgvc-secure-wrapper.html` - Página wrapper principal
- `secure-token-manager.js` - Gerenciador de tokens seguros

### Backend (Produção)
- `api/get-token.php` - Endpoint seguro para geração de tokens
- `api/.htaccess` - Configurações de segurança Apache

## Instalação

### 1. Backend (Cloudflare Pages - Recomendado)

A infraestrutura foi adaptada para rodar nativamente na Cloudflare Pages usando "Pages Functions", dispensando o uso de PHP, alcançando latência menor e escalabilidade global.

1. **Configuração do Repositório**:
   - Suba todos os arquivos para um repositório no GitHub/GitLab (incluindo a pasta `functions/`).
2. **Deploy na Cloudflare**:
   - No painel da Cloudflare, vá em **Workers & Pages** -> **Create application** -> selecione a aba **Pages**.
   - Conecte ao seu repositório Git.
   - Deixe o *Build command* vazio e *Build output directory* vazio (apontando p/ a raiz).
3. **Variáveis de Ambiente (Environment Variables)**:
   - Configure em **Settings -> Environment variables** no seu projeto do Pages:
     - `SIGMACHAT_TOKEN`: 'seu-token-real'
     - `BACKEND_AUTH_TOKEN`: 'sua-chave-secreta'
     - `SIGMACHAT_BASE_URL`: 'https://webhookdidactica.sigmalabs.com.br/webhook/gvc-chatbot'

#### Alternativa: Deploy via Wrangler CLI (Rápido)
1. Instale o Wrangler: `npm install -g wrangler`
2. No terminal do projeto, rode: `wrangler pages deploy . --project-name chatgvc-secure-wrapper`
3. Configure as variáveis pelo painel da Cloudflare.

### 2. Backend Tradicional (PHP - Obsoleto)

Caso ainda precise usar hospedagem tradicional via PHP, veja a pasta `api/` e os scripts originais. No entanto, para Cloudflare, o PHP não é necessário de forma alguma.

### 2. Frontend

1. Hospede os arquivos do wrapper:
   ```
   /secure-wrapper/
     ├── chatgvc-secure-wrapper.html
     ├── secure-token-manager.js
     └── ge-avatar.png (opcional)
   ```

2. No `secure-token-manager.js`, configure:
   ```javascript
   CONFIG.backendUrl = 'https://seu-dominio.com/api/get-token.php';
   CONFIG.useBackend = true;
   ```

## Uso

### Opção 1: Iframe (Recomendado)

```html
<iframe
  src="https://seu-dominio.com/secure-wrapper/chatgvc-secure-wrapper.html"
  style="position:fixed; bottom:0; right:0; width:420px; height:650px; border:none; z-index:9999;"
  allow="clipboard-write"
  title="Chat GVC"
></iframe>
```

### Opção 2: Script Embed

```html
<script>
  (function() {
    // NÃO exponha o token real aqui - use sempre o wrapper!
    var wrapperUrl = 'https://seu-dominio.com/secure-wrapper/chatgvc-secure-wrapper.html';
    
    var script = document.createElement('script');
    script.src = wrapperUrl.replace('.html', '.js');
    script.setAttribute('data-wrapper-url', wrapperUrl);
    document.body.appendChild(script);
  })();
</script>
```

## Medidas de Segurança Implementadas

### 1. Obfuscação de Configuração
- Tokens codificados em Base64
- URLs indirectas
- Sem exposição de dados sensíveis no source code

### 2. Gerenciamento de Token
- Expiração automática (5 minutos)
- Refresh automático antes da expiração
- Armazenamento em memória (não localStorage)

### 3. Headers de Segurança
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- CSP headers (configurável)

### 4. CORS Controlado
- Apenas origens autorizadas
- Headers customizados para validação
- Sem credenciais expostas

### 5. Validação de Sessão
- ID de sessão único por navegação
- Correlação ID para requisições
- Hash de integridade

## Configuração PHP

```php
// Constantes obrigatórias
define('SIGMACHAT_TOKEN', 'wN7tZgOlxvN9OrLo');  // Token real
define('BACKEND_AUTH_TOKEN', 'chave-secreta'); // Para HMAC

// URLs permitidas (CORS)
$allowedOrigins = [
    'https://seu-dominio.com',
    'https://www.seu-dominio.com',
];
```

## Troubleshooting

### Token não funciona
1. Verifique se o backend está acessível
2. Check o console do navegador para erros
3. Valide se o token não expirou

### CORS error
1. Confirme que o domínio está na lista de origens permitidas
2. Verifique se o `.htaccess` está sendo processado

### Wrapper não carrega
1. Verifique se os arquivos estão no caminho correto
2. Confirme que o HTTPS está funcionando
3. Check logs do servidor

## Segurança Adicional Recomendada

1. **Use HTTPS sempre** - HTTP não é suportado
2. **Minimize o JS** - Dificulta análise reverse
3. **Rode em subdomain separado** - Isolamento de segurança
4. **Implemente rate limiting** - Proteção contra abuso
5. **Monitore logs** - Detecte anomalias

## Compatibilidade

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+
- IE 11 (com polyfills)

## Licença

Proprietário - Didactica GVC
