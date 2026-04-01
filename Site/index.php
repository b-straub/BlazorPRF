<?php
/**
 * PRF-Authenticated PHP Backend
 * Single entry point for all API requests.
 */

// Suppress xdebug HTML output in API responses
ini_set('html_errors', '0');

require_once __DIR__ . '/lib/Database.php';
require_once __DIR__ . '/lib/Auth.php';
require_once __DIR__ . '/lib/Response.php';
require_once __DIR__ . '/actions/SendMail.php';
require_once __DIR__ . '/actions/TestSmtp.php';
require_once __DIR__ . '/actions/TestImap.php';

use Lib\Database;
use Lib\Auth;
use Lib\Response;
use Actions\SendMail;
use Actions\TestSmtp;
use Actions\TestImap;

// Load configuration from secure directory
$config = require __DIR__ . '/secure/config.php';

// Set CORS headers
Response::cors($config['allowedOrigins']);

// Handle preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    Response::preflight();
}

// Initialize database and auth
$db = new Database($config['dbPath']);
$auth = new Auth($db, $config['timestampTolerance']);

// Get request info
$headers = getallheaders();
$method = $_SERVER['REQUEST_METHOD'];
$path = $_GET['path'] ?? '';
$parts = explode('/', trim($path, '/'));
$endpoint = $parts[0] ?? '';
$body = file_get_contents('php://input');

// Route to handlers
switch ($endpoint) {
    case '':
        // Health check
        Response::success([
            'status' => 'ok',
            'service' => 'PRF Mail Backend',
            'time' => gmdate('c')
        ]);
        break;

    case 'admin-setup':
        handleAdminSetup($auth, $method, $body);
        break;

    case 'register':
        handleRegister($auth, $db, $method, $headers, $body);
        break;

    case 'keys':
        handleKeys($auth, $db, $method, $headers, $body);
        break;

    case 'profile':
        handleProfile($auth, $db, $method, $headers, $body);
        break;

    default:
        // All other endpoints require user authentication
        handleAction($auth, $db, $endpoint, $method, $headers, $body);
        break;
}

/**
 * Admin setup - check if admin is configured (via secure/admin_keys.json file)
 */
function handleAdminSetup(Auth $auth, string $method, string $body): void
{
    if ($method !== 'GET') {
        Response::error('Method not allowed', 405);
    }

    Response::success([
        'hasAdmin' => $auth->hasAdmin(),
        'note' => 'Admin key is configured via secure/admin_keys.json file (SSH/manual install)'
    ]);
}

/**
 * Register a public key (admin only)
 */
function handleRegister(Auth $auth, Database $db, string $method, array $headers, string $body): void
{
    // Verify admin auth
    $result = $auth->verifyAdminRequest($headers, $method, $body);
    if (!$result->success) {
        Response::error($result->error ?? 'Admin authentication required', 401);
    }

    if ($method === 'GET') {
        // List all registered keys
        Response::success([
            'keys' => $db->listPublicKeys()
        ]);
    }

    if ($method !== 'POST') {
        Response::error('Method not allowed', 405);
    }

    $request = json_decode($body, true);
    if ($request === null) {
        Response::error('Invalid JSON', 400);
    }

    $keyId = $request['keyId'] ?? $request['publicKey'] ?? '';
    $publicKey = $request['publicKey'] ?? $keyId;
    $userId = $request['userId'] ?? '';

    if (empty($keyId) || empty($publicKey)) {
        Response::error('keyId/publicKey required', 400);
    }

    $db->storePublicKey($keyId, $publicKey, $userId);

    Response::success([
        'success' => true,
        'keyId' => $keyId
    ]);
}

/**
 * Manage keys (admin only) - revoke, list
 */
function handleKeys(Auth $auth, Database $db, string $method, array $headers, string $body): void
{
    // Verify admin auth
    $result = $auth->verifyAdminRequest($headers, $method, $body);
    if (!$result->success) {
        Response::error($result->error ?? 'Admin authentication required', 401);
    }

    if ($method === 'GET') {
        Response::success([
            'keys' => $db->listPublicKeys()
        ]);
    }

    if ($method === 'DELETE') {
        $keyId = $_GET['keyId'] ?? '';
        if (empty($keyId)) {
            Response::error('keyId required', 400);
        }

        $revoked = $db->revokePublicKey($keyId);
        Response::success([
            'success' => $revoked,
            'keyId' => $keyId
        ]);
    }

    Response::error('Method not allowed', 405);
}

/**
 * Sync encrypted profile (user authenticated).
 * GET = retrieve, POST = save (last write wins).
 * The profile is encrypted client-side — server only stores the blob.
 */
function handleProfile(Auth $auth, Database $db, string $method, array $headers, string $body): void
{
    // Verify user auth
    $result = $auth->verifyRequest($headers, $method, $body);
    if (!$result->success) {
        Response::error($result->error ?? 'Authentication required', 401);
    }

    if ($method === 'GET') {
        $profile = $db->getProfile($result->keyId);
        Response::success([
            'profile' => $profile
        ]);
    }

    if ($method === 'POST') {
        $request = json_decode($body, true);
        if ($request === null || empty($request['encryptedProfile'])) {
            Response::error('encryptedProfile required', 400);
        }

        // Minimum sanity check — encrypted profile should be valid JSON (SymmetricEncryptedMessage)
        $profileData = $request['encryptedProfile'];
        if (strlen($profileData) < 50 || json_decode($profileData) === null) {
            Response::error('Invalid profile data', 400);
        }

        $saved = $db->saveProfile($result->keyId, $profileData);
        Response::success([
            'success' => $saved
        ]);
    }

    Response::error('Method not allowed', 405);
}

/**
 * Handle authenticated actions (send_mail, test_mail, etc.)
 * SMTP credentials come from request params, not server config.
 */
function handleAction(Auth $auth, Database $db, string $action, string $method, array $headers, string $body): void
{
    if ($method !== 'POST') {
        Response::error('Method not allowed', 405);
    }

    // Verify user auth
    $result = $auth->verifyRequest($headers, $method, $body);
    if (!$result->success) {
        Response::error($result->error ?? 'Authentication required', 401);
    }

    // Parse body as JSON
    $request = json_decode($body, true);
    if ($request === null) {
        Response::error('Invalid JSON', 400);
    }

    $params = $request['params'] ?? $request;

    // Execute action - mail settings come from request params
    switch ($action) {
        case 'send_mail':
            $handler = new SendMail();
            $actionResult = $handler->execute($params, $result->keyId);
            break;

        case 'test_smtp':
            $handler = new TestSmtp();
            $actionResult = $handler->execute($params, $result->keyId);
            break;

        case 'test_imap':
            $handler = new TestImap();
            $actionResult = $handler->execute($params, $result->keyId);
            break;

        default:
            Response::error('Unknown action', 404);
    }

    if ($actionResult['success']) {
        Response::success($actionResult);
    } else {
        Response::error($actionResult['error'] ?? 'Action failed', 400);
    }
}
