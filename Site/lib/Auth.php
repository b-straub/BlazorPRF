<?php

namespace Lib;

require_once __DIR__ . '/../PrfCrypto/PrfCrypto.php';

use PrfCrypto\PrfCrypto;

class VerificationResult
{
    public bool $success;
    public ?string $error;
    public ?string $keyId;
    public ?array $payload;

    public function __construct(
        bool $success,
        ?string $error = null,
        ?string $keyId = null,
        ?array $payload = null
    ) {
        $this->success = $success;
        $this->error = $error;
        $this->keyId = $keyId;
        $this->payload = $payload;
    }
}

class Auth
{
    private Database $db;
    private int $timestampTolerance;
    private string $secureDir;
    private ?string $adminPublicKey = null;

    public function __construct(Database $db, int $timestampTolerance = 300)
    {
        $this->db = $db;
        $this->timestampTolerance = $timestampTolerance;
        $this->secureDir = __DIR__ . '/../secure';
        $this->adminPublicKey = $this->loadAdminKey();
    }

    /**
     * Verify a signed request (header-based).
     */
    public function verifyRequest(array $headers, string $method, string $body): VerificationResult
    {
        // Clean expired nonces on each request
        $this->db->cleanExpiredNonces($this->timestampTolerance);

        // Get signature headers
        $publicKey = $this->getHeader($headers, 'X-Public-Key');
        $timestamp = $this->getHeader($headers, 'X-Timestamp');
        $nonce = $this->getHeader($headers, 'X-Nonce');
        $bodyHash = $this->getHeader($headers, 'X-BodyHash');
        $signature = $this->getHeader($headers, 'X-Signature');

        // Validate structure
        if (empty($publicKey) || empty($timestamp) || empty($nonce) || empty($signature)) {
            return new VerificationResult(false, 'Missing signature headers');
        }

        // Validate public key format
        if (!PrfCrypto::isValidEd25519PublicKey($publicKey)) {
            return new VerificationResult(false, 'Invalid public key format');
        }

        // Validate timestamp
        $requestTime = intval($timestamp);
        if (!$this->validateTimestamp($requestTime)) {
            return new VerificationResult(false, 'Request timestamp expired');
        }

        // Validate nonce not reused
        if ($this->db->isNonceUsed($nonce)) {
            return new VerificationResult(false, 'Nonce already used');
        }

        // Validate body hash
        $expectedBodyHash = base64_encode(hash('sha256', $body, true));
        if ($bodyHash !== $expectedBodyHash) {
            return new VerificationResult(false, 'Body hash mismatch');
        }

        // Look up public key - check if registered
        $storedKey = $this->db->getPublicKey($publicKey);
        if ($storedKey === null) {
            return new VerificationResult(false, 'Public key not registered');
        }

        // Build signed message: method|timestamp|nonce|bodyHash
        $message = "$method|$timestamp|$nonce|$bodyHash";

        // Verify signature
        if (!PrfCrypto::verify($message, $signature, $publicKey)) {
            return new VerificationResult(false, 'Invalid signature');
        }

        // Store nonce after successful verification
        $this->db->storeNonce($nonce, $requestTime);

        return new VerificationResult(true, null, $publicKey, null);
    }

    /**
     * Verify admin signature (from secure/admin_keys.json).
     */
    public function verifyAdminRequest(array $headers, string $method, string $body): VerificationResult
    {
        // Check admin key is configured
        if ($this->adminPublicKey === null) {
            return new VerificationResult(false, 'Admin not configured');
        }

        // Clean expired nonces
        $this->db->cleanExpiredNonces($this->timestampTolerance);

        // Get admin signature headers
        $publicKey = $this->getHeader($headers, 'X-Admin-PublicKey');
        $timestamp = $this->getHeader($headers, 'X-Admin-Timestamp');
        $nonce = $this->getHeader($headers, 'X-Admin-Nonce');
        $bodyHash = $this->getHeader($headers, 'X-Admin-BodyHash');
        $signature = $this->getHeader($headers, 'X-Admin-Signature');

        // Validate structure
        if (empty($publicKey) || empty($timestamp) || empty($nonce) || empty($signature)) {
            return new VerificationResult(false, 'Missing admin signature headers');
        }

        // Validate public key format
        if (!PrfCrypto::isValidEd25519PublicKey($publicKey)) {
            return new VerificationResult(false, 'Invalid admin public key format');
        }

        // Check public key matches admin
        if ($publicKey !== $this->adminPublicKey) {
            return new VerificationResult(false, 'Not the admin key');
        }

        // Validate timestamp
        $requestTime = intval($timestamp);
        if (!$this->validateTimestamp($requestTime)) {
            return new VerificationResult(false, 'Admin request timestamp expired');
        }

        // Validate nonce not reused
        if ($this->db->isNonceUsed($nonce)) {
            return new VerificationResult(false, 'Admin nonce already used');
        }

        // Validate body hash
        $expectedBodyHash = base64_encode(hash('sha256', $body, true));
        if ($bodyHash !== $expectedBodyHash) {
            return new VerificationResult(false, 'Admin body hash mismatch');
        }

        // Build signed message
        $message = "$method|$timestamp|$nonce|$bodyHash";

        // Verify signature
        if (!PrfCrypto::verify($message, $signature, $publicKey)) {
            return new VerificationResult(false, 'Invalid admin signature');
        }

        // Store nonce after successful verification
        $this->db->storeNonce($nonce, $requestTime);

        return new VerificationResult(true, null, 'admin', null);
    }

    /**
     * Check if admin is configured.
     */
    public function hasAdmin(): bool
    {
        return $this->adminPublicKey !== null;
    }

    /**
     * Get the admin public key (for diagnostics).
     */
    public function getAdminPublicKey(): ?string
    {
        return $this->adminPublicKey;
    }

    /**
     * Load and parse the admin key from secure/admin_keys.json.
     * Supports PFA armored format.
     */
    private function loadAdminKey(): ?string
    {
        $file = $this->secureDir . '/admin_keys.json';
        if (!file_exists($file)) {
            return null;
        }

        $content = file_get_contents($file);
        $data = json_decode($content, true);

        if ($data === null || !isset($data['admin'])) {
            return null;
        }

        $adminKey = $data['admin'];

        // Check if it's armored format
        if (str_contains($adminKey, '-----BEGIN PFA PUBLIC KEY-----')) {
            $key = $this->unArmorPublicKey($adminKey);
        } else {
            // Raw base64 key
            $key = trim($adminKey);
        }

        // Validate extracted key is actually a valid Ed25519 public key
        if ($key !== null && !PrfCrypto::isValidEd25519PublicKey($key)) {
            return null;
        }

        return $key;
    }

    /**
     * Extract base64 public key from PFA armored format.
     * Format: -----BEGIN PFA PUBLIC KEY-----\n\nbase64payload\n-----END PFA PUBLIC KEY-----
     * Payload is base64(JSON with "k" = actual key)
     */
    private function unArmorPublicKey(string $armored): ?string
    {
        $header = '-----BEGIN PFA PUBLIC KEY-----';
        $footer = '-----END PFA PUBLIC KEY-----';

        $headerPos = strpos($armored, $header);
        $footerPos = strpos($armored, $footer);

        if ($headerPos === false || $footerPos === false || $footerPos <= $headerPos) {
            return null;
        }

        // Extract content between header and footer
        $content = substr($armored, $headerPos + strlen($header), $footerPos - $headerPos - strlen($header));

        // Remove all whitespace
        $base64Payload = preg_replace('/\s+/', '', $content);

        if (empty($base64Payload)) {
            return null;
        }

        // Decode outer base64
        $jsonBytes = base64_decode($base64Payload, true);
        if ($jsonBytes === false) {
            // Maybe it's legacy format (raw key)
            return $base64Payload;
        }

        // Check if it's JSON
        if ($jsonBytes[0] === '{') {
            $payload = json_decode($jsonBytes, true);
            if ($payload !== null && isset($payload['k'])) {
                return $payload['k'];
            }
        }

        // Legacy format: the content itself is the base64 key
        return $base64Payload;
    }

    private function validateTimestamp(int $timestamp): bool
    {
        $now = time();
        return abs($now - $timestamp) <= $this->timestampTolerance;
    }

    private function getHeader(array $headers, string $name): string
    {
        // Try exact match first
        if (isset($headers[$name])) {
            return $headers[$name];
        }

        // Try case-insensitive match
        $lowerName = strtolower($name);
        foreach ($headers as $key => $value) {
            if (strtolower($key) === $lowerName) {
                return $value;
            }
        }

        return '';
    }
}
