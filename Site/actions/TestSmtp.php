<?php

namespace Actions;

/**
 * Test SMTP connection with user-provided credentials.
 * Does not send actual email, just verifies connection and auth.
 */
class TestSmtp
{
    /**
     * Execute the test_smtp action.
     *
     * @param array $params Expected: smtpHost, smtpPort, smtpUsername, smtpPassword
     * @param string $keyId The authenticated key ID
     * @return array Result with success status
     */
    public function execute(array $params, string $keyId): array
    {
        $host = $params['smtpHost'] ?? '';
        $port = (int)($params['smtpPort'] ?? 587);
        $username = $params['smtpUsername'] ?? '';
        $password = $params['smtpPassword'] ?? '';

        if (empty($host)) {
            return ['success' => false, 'error' => 'SMTP host is required'];
        }

        if (empty($username)) {
            return ['success' => false, 'error' => 'SMTP username is required'];
        }

        if (empty($password)) {
            return ['success' => false, 'error' => 'SMTP password is required'];
        }

        // Block SSRF via private/reserved IP ranges
        $resolvedIp = gethostbyname($host);
        if (!filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['success' => false, 'error' => 'SMTP host resolves to a private/reserved IP address'];
        }

        // Test SMTP connection
        $timeout = 10;
        $context = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $host,
            ]
        ]);

        try {
            // Determine if we should use SSL/TLS
            $useTls = $port === 587;
            $useSsl = $port === 465;

            if ($useSsl) {
                $socket = @stream_socket_client(
                    "ssl://$host:$port",
                    $errno,
                    $errstr,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $context
                );
            } else {
                $socket = @stream_socket_client(
                    "tcp://$host:$port",
                    $errno,
                    $errstr,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $context
                );
            }

            if (!$socket) {
                return [
                    'success' => false,
                    'error' => 'Connection failed'
                ];
            }

            // Read greeting
            $greeting = $this->readResponse($socket);
            if (!str_starts_with($greeting, '220')) {
                fclose($socket);
                return [
                    'success' => false,
                    'error' => 'SMTP server rejected connection'
                ];
            }

            // Send EHLO
            $this->sendCommand($socket, "EHLO localhost");
            $ehloResponse = $this->readResponse($socket);
            if (!str_starts_with($ehloResponse, '250')) {
                fclose($socket);
                return [
                    'success' => false,
                    'error' => 'EHLO failed'
                ];
            }

            // STARTTLS if port 587
            if ($useTls) {
                $this->sendCommand($socket, "STARTTLS");
                $starttlsResponse = $this->readResponse($socket);
                if (!str_starts_with($starttlsResponse, '220')) {
                    fclose($socket);
                    return [
                        'success' => false,
                        'error' => 'STARTTLS failed'
                    ];
                }

                // Upgrade to TLS
                $cryptoResult = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                if (!$cryptoResult) {
                    fclose($socket);
                    return [
                        'success' => false,
                        'error' => 'TLS negotiation failed'
                    ];
                }

                // Re-send EHLO after STARTTLS
                $this->sendCommand($socket, "EHLO localhost");
                $this->readResponse($socket);
            }

            // AUTH LOGIN
            $this->sendCommand($socket, "AUTH LOGIN");
            $authResponse = $this->readResponse($socket);
            if (!str_starts_with($authResponse, '334')) {
                fclose($socket);
                return [
                    'success' => false,
                    'error' => 'AUTH LOGIN not supported'
                ];
            }

            // Send username (base64)
            $this->sendCommand($socket, base64_encode($username));
            $userResponse = $this->readResponse($socket);
            if (!str_starts_with($userResponse, '334')) {
                fclose($socket);
                return [
                    'success' => false,
                    'error' => 'Authentication failed'
                ];
            }

            // Send password (base64)
            $this->sendCommand($socket, base64_encode($password));
            $passResponse = $this->readResponse($socket);
            if (!str_starts_with($passResponse, '235')) {
                fclose($socket);
                return [
                    'success' => false,
                    'error' => 'Authentication failed: Invalid credentials'
                ];
            }

            // QUIT
            $this->sendCommand($socket, "QUIT");
            fclose($socket);

            return [
                'success' => true,
                'message' => 'SMTP connection and authentication successful',
                'host' => $host,
                'port' => $port
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => 'Connection error'
            ];
        }
    }

    private function sendCommand($socket, string $command): void
    {
        fwrite($socket, $command . "\r\n");
    }

    private function readResponse($socket): string
    {
        $response = '';
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            // Check if this is the last line (no continuation)
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }
        return trim($response);
    }
}
