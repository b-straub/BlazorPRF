<?php

use Valet\Drivers\BasicValetDriver;

class LocalValetDriver extends BasicValetDriver
{
    /**
     * Determine if the driver serves the request.
     */
    public function serves(string $sitePath, string $siteName, string $uri): bool
    {
        return true;
    }

    /**
     * Determine if the incoming request is for a static file.
     */
    public function isStaticFile(string $sitePath, string $siteName, string $uri)
    {
        // Deny access to secure directory
        if (str_starts_with($uri, '/secure/')) {
            return false;
        }

        // Deny access to data directory
        if (str_starts_with($uri, '/data/')) {
            return false;
        }

        // Check for actual static files
        if (file_exists($sitePath . $uri) && is_file($sitePath . $uri)) {
            return $sitePath . $uri;
        }

        return false;
    }

    /**
     * Get the fully resolved path to the application's front controller.
     */
    public function frontControllerPath(string $sitePath, string $siteName, string $uri): ?string
    {
        // Deny access to secure directory
        if (str_starts_with($uri, '/secure/')) {
            http_response_code(403);
            die(json_encode(['error' => 'Forbidden']));
        }

        // Deny access to data directory
        if (str_starts_with($uri, '/data/')) {
            http_response_code(403);
            die(json_encode(['error' => 'Forbidden']));
        }

        // Route /api/* to index.php with path parameter
        if (preg_match('#^/api/(.*)$#', $uri, $matches)) {
            $_GET['path'] = $matches[1];
            return $sitePath . '/index.php';
        }

        // Default routing
        if (file_exists($sitePath . $uri) && is_file($sitePath . $uri)) {
            return $sitePath . $uri;
        }

        // Default to index.php if it exists
        if (file_exists($sitePath . '/index.php')) {
            return $sitePath . '/index.php';
        }

        return null;
    }
}
