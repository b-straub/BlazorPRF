<?php

namespace Lib;

class Response
{
    public static function success(array $data): never
    {
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    public static function error(string $message, int $httpCode = 401): never
    {
        http_response_code($httpCode);
        header('Content-Type: application/json');
        echo json_encode(['error' => $message]);
        exit;
    }

    public static function cors(array $allowedOrigins): void
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

        if (in_array($origin, $allowedOrigins, true)) {
            header("Access-Control-Allow-Origin: $origin");
        }

        header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Public-Key, X-Timestamp, X-Nonce, X-BodyHash, X-Signature, X-Admin-PublicKey, X-Admin-Timestamp, X-Admin-Nonce, X-Admin-BodyHash, X-Admin-Signature');
        header('Access-Control-Max-Age: 86400');
    }

    public static function preflight(): never
    {
        http_response_code(204);
        exit;
    }
}
