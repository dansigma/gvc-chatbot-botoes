<?php
/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║  ChatGVC - Secure Token Endpoint                                           ║
 * ║                                                                            ║
 * ║  Este arquivo deve ser hospedado em seu servidor backend seguro.            ║
 * ║  Ele é responsável por obter tokens do SigmaChat sem expô-los ao cliente.    ║
 * ║                                                                            ║
 * ║  INSTRUÇÕES:                                                               ║
 * ║  1. Hospede este arquivo em seu domínio seguro (HTTPS)                    ║
 * ║  2. Configure as constantes SIGMACHAT_* com os valores reais                 ║
 * ║  3. Configure BACKEND_AUTH_TOKEN com uma chave secreta para API           ║
 * ║  4. Adicione regras no .htaccess ou nginx para proteger este endpoint     ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 */

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURAÇÕES (MUDE ESTES VALORES)
// ═══════════════════════════════════════════════════════════════════════════════

// Token real do SigmaChat (NUNCA envie isso ao cliente!)
define('SIGMACHAT_TOKEN', 'wN7tZgOlxvN9OrLo');

// URL base do SigmaChat
define('SIGMACHAT_BASE_URL', 'https://webhookdidactica.sigmalabs.com.br/webhook/gvc-chatbot');

// Chave secreta para autenticar requisições do wrapper
define('BACKEND_AUTH_TOKEN', 'sua-chave-secreta-backend-mude-isso');

// Tempo de expiração do token gerado (em segundos)
define('TOKEN_EXPIRY', 300); // 5 minutos

// ═══════════════════════════════════════════════════════════════════════════════
// HEADERS DE SEGURANÇA
// ═══════════════════════════════════════════════════════════════════════════════

// Prevenir caching
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');

// Prevenir clickjacking
header('X-Frame-Options: DENY');

// Prevenir MIME type sniffing
header('X-Content-Type-Options: nosniff');

// Content type
header('Content-Type: application/json; charset=utf-8');

// ═══════════════════════════════════════════════════════════════════════════════
// FUNÇÕES AUXILIARES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Gera um token seguro com hash HMAC
 */
function generateSecureToken($sessionId)
{
    $expiry = time() + TOKEN_EXPIRY;
    $payload = [
        'sid' => $sessionId,
        'exp' => $expiry,
        'iat' => time(),
        'jti' => bin2hex(random_bytes(16))
    ];

    // Criar signature
    $dataToSign = json_encode($payload) . SIGMACHAT_TOKEN;
    $signature = hash_hmac('sha256', $dataToSign, BACKEND_AUTH_TOKEN);

    // Codificar tudo em Base64 (não é criptografia, apenas obfuscação)
    $tokenData = [
        'payload' => $payload,
        'signature' => $signature
    ];

    return [
        'token' => base64_encode(json_encode($tokenData)),
        'expiresIn' => TOKEN_EXPIRY,
        'expiresAt' => $expiry
    ];
}

/**
 * Valida um token existente e gera um novo (refresh)
 */
function refreshToken($oldToken)
{
    // Validar formato do token antigo
    $decoded = @base64_decode($oldToken);
    if (!$decoded) {
        return null;
    }

    $tokenData = @json_decode($decoded, true);
    if (!$tokenData || !isset($tokenData['payload'])) {
        return null;
    }

    // Validar signature do token antigo
    $dataToSign = json_encode($tokenData['payload']) . SIGMACHAT_TOKEN;
    $expectedSignature = hash_hmac('sha256', $dataToSign, BACKEND_AUTH_TOKEN);

    if (!hash_equals($expectedSignature, $tokenData['signature'])) {
        return null;
    }

    // Gerar novo token
    return generateSecureToken($tokenData['payload']['sid']);
}

/**
 * Retorna erro JSON
 */
function returnError($message, $statusCode = 400)
{
    http_response_code($statusCode);
    echo json_encode([
        'error' => true,
        'message' => $message
    ]);
    exit;
}

/**
 * Valida o origin da requisição (CORS)
 */
function validateOrigin()
{
    // Em produção, liste os domínios autorizados
    $allowedOrigins = [
        'https://seu-dominio.com',
        'https://www.seu-dominio.com',
        // Adicione outros domínios conforme necessário
    ];

    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    // Para desenvolvimento, permitir qualquer origin
    // REMOVA ESTA LINHA EM PRODUÇÃO!
    if (in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1'])) {
        return true;
    }

    if (in_array($origin, $allowedOrigins)) {
        header("Access-Control-Allow-Origin: $origin");
        return true;
    }

    return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROCESSAMENTO DA REQUISIÇÃO
// ═══════════════════════════════════════════════════════════════════════════════

// Validar método HTTP
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && $_SERVER['REQUEST_METHOD'] !== 'OPTIONS') {
    returnError('Método não permitido', 405);
}

// Handle CORS preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Id');
    header('Access-Control-Max-Age: 86400');
    exit;
}

// Validar Origin
if (!validateOrigin()) {
    returnError('Origin não autorizado', 403);
}

// Obter sessão do cliente
$sessionId = $_SERVER['HTTP_X_SESSION_ID'] ?? session_id();

// Determinar ação
$action = $_POST['action'] ?? $_GET['action'] ?? 'generate';

// Processar ação
switch ($action) {
    case 'generate':
        // Gerar novo token
        $tokenInfo = generateSecureToken($sessionId);
        echo json_encode($tokenInfo);
        break;

    case 'refresh':
        // Renovar token existente
        $oldToken = $_POST['token'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $oldToken = str_replace('Bearer ', '', $oldToken);

        $newTokenInfo = refreshToken($oldToken);
        if ($newTokenInfo) {
            echo json_encode($newTokenInfo);
        }
        else {
            // Token inválido - gerar novo mesmo assim
            $tokenInfo = generateSecureToken($sessionId);
            echo json_encode($tokenInfo);
        }
        break;

    case 'script':
        // Retornar URL do script SigmaChat com token
        // Esta é a parte crítica: o token real só vai para o script
        $scriptUrl = SIGMACHAT_BASE_URL . '?token=' . urlencode(SIGMACHAT_TOKEN) . '&version=v1';
        echo json_encode([
            'scriptUrl' => $scriptUrl,
            'config' => [
                'buttonText' => 'Vamos conversar?',
                'buttonColor' => '#153861',
                'buttonTextColor' => '#fff',
                'buttonEffect' => true
            ]
        ]);
        break;

    case 'validate':
        // Validar se o token existe e é válido
        $token = $_POST['token'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $token = str_replace('Bearer ', '', $token);

        $decoded = @base64_decode($token);
        if ($decoded) {
            $tokenData = @json_decode($decoded, true);
            if ($tokenData && isset($tokenData['payload']['exp'])) {
                $isValid = $tokenData['payload']['exp'] > time();
                echo json_encode([
                    'valid' => $isValid,
                    'expiresAt' => $tokenData['payload']['exp'],
                    'timeRemaining' => max(0, $tokenData['payload']['exp'] - time())
                ]);
            }
            else {
                echo json_encode(['valid' => false]);
            }
        }
        else {
            echo json_encode(['valid' => false]);
        }
        break;

    default:
        returnError('Ação não reconhecida', 400);
}
