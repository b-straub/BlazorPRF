<?php

namespace Actions;

/**
 * Send email using user-provided SMTP credentials.
 * All SMTP settings come from the request, nothing from server config.
 */
class SendMail
{
    /**
     * Execute the send_mail action.
     *
     * @param array $params Expected: to, subject, body, fromEmail, fromName,
     *                      smtpHost, smtpPort, smtpUsername, smtpPassword,
     *                      replyTo (optional)
     * @param string $keyId The authenticated key ID
     * @return array Result with success status
     */
    public function execute(array $params, string $keyId): array
    {
        // Validate required mail params
        $to = $params['to'] ?? '';
        $subject = $params['subject'] ?? '';
        $body = $params['body'] ?? '';
        $replyTo = $params['replyTo'] ?? null;
        $fromEmail = $params['fromEmail'] ?? '';
        $fromName = $params['fromName'] ?? '';

        // SMTP settings from request
        $smtpHost = $params['smtpHost'] ?? '';
        $smtpPort = (int)($params['smtpPort'] ?? 587);
        $smtpUsername = $params['smtpUsername'] ?? '';
        $smtpPassword = $params['smtpPassword'] ?? '';

        if (empty($to)) {
            return ['success' => false, 'error' => 'Recipient (to) is required'];
        }

        if (!filter_var($to, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'Invalid recipient email'];
        }

        if (empty($subject)) {
            return ['success' => false, 'error' => 'Subject is required'];
        }

        if (empty($body)) {
            return ['success' => false, 'error' => 'Body is required'];
        }

        if (empty($fromEmail)) {
            return ['success' => false, 'error' => 'From email is required'];
        }

        if (!filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'Invalid from email'];
        }

        if (empty($smtpHost)) {
            return ['success' => false, 'error' => 'SMTP host is required'];
        }

        if (empty($smtpUsername) || empty($smtpPassword)) {
            return ['success' => false, 'error' => 'SMTP credentials are required'];
        }

        // Sanitize header-injectable values (strip CR/LF)
        $subject = str_replace(["\r", "\n"], '', $subject);
        $fromName = str_replace(["\r", "\n"], '', $fromName);
        if ($replyTo !== null) {
            $replyTo = str_replace(["\r", "\n"], '', $replyTo);
        }

        // Block SSRF via private/reserved IP ranges and use resolved IP for connection
        $resolvedIp = gethostbyname($smtpHost);
        if ($this->isPrivateIp($resolvedIp)) {
            return ['success' => false, 'error' => 'SMTP host resolves to a private/reserved IP address'];
        }

        // Send via SMTP — connect using resolved IP to prevent DNS rebinding
        try {
            $result = $this->sendSmtp(
                $resolvedIp,
                $smtpPort,
                $smtpUsername,
                $smtpPassword,
                $fromEmail,
                $fromName,
                $to,
                $subject,
                $body,
                $replyTo,
                $keyId,
                $smtpHost
            );

            return $result;
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => 'Send failed'
            ];
        }
    }

    /**
     * Send email via SMTP with authentication.
     */
    private function sendSmtp(
        string $host,
        int $port,
        string $username,
        string $password,
        string $fromEmail,
        string $fromName,
        string $to,
        string $subject,
        string $body,
        ?string $replyTo,
        string $keyId,
        string $tlsHostname = ''
    ): array {
        $timeout = 30;
        // Use original hostname for TLS cert validation (host may be resolved IP)
        $peerName = !empty($tlsHostname) ? $tlsHostname : $host;

        // Connect
        $useSsl = $port === 465;
        $socketAddr = $useSsl ? "ssl://$host:$port" : "tcp://$host:$port";

        $sslContext = stream_context_create([
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'peer_name' => $peerName,
            ]
        ]);

        $socket = @stream_socket_client($socketAddr, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $sslContext);
        if (!$socket) {
            return ['success' => false, 'error' => 'Connection failed'];
        }

        // Read greeting
        $greeting = $this->readResponse($socket);
        if (!str_starts_with($greeting, '220')) {
            fclose($socket);
            return ['success' => false, 'error' => 'SMTP server rejected connection'];
        }

        // EHLO
        $this->sendCommand($socket, "EHLO localhost");
        $ehlo = $this->readResponse($socket);
        if (!str_starts_with($ehlo, '250')) {
            fclose($socket);
            return ['success' => false, 'error' => 'EHLO failed'];
        }

        // STARTTLS for port 587
        if ($port === 587) {
            $this->sendCommand($socket, "STARTTLS");
            $starttls = $this->readResponse($socket);
            if (!str_starts_with($starttls, '220')) {
                fclose($socket);
                return ['success' => false, 'error' => 'STARTTLS failed'];
            }

            if (!@stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                fclose($socket);
                return ['success' => false, 'error' => 'TLS negotiation failed'];
            }

            // Re-EHLO after TLS
            $this->sendCommand($socket, "EHLO localhost");
            $this->readResponse($socket);
        }

        // AUTH LOGIN
        $this->sendCommand($socket, "AUTH LOGIN");
        $auth = $this->readResponse($socket);
        if (!str_starts_with($auth, '334')) {
            fclose($socket);
            return ['success' => false, 'error' => 'AUTH not supported'];
        }

        $this->sendCommand($socket, base64_encode($username));
        $userResp = $this->readResponse($socket);
        if (!str_starts_with($userResp, '334')) {
            fclose($socket);
            return ['success' => false, 'error' => 'Authentication failed'];
        }

        $this->sendCommand($socket, base64_encode($password));
        $passResp = $this->readResponse($socket);
        if (!str_starts_with($passResp, '235')) {
            fclose($socket);
            return ['success' => false, 'error' => 'Invalid credentials'];
        }

        // MAIL FROM
        $this->sendCommand($socket, "MAIL FROM:<$fromEmail>");
        $mailFrom = $this->readResponse($socket);
        if (!str_starts_with($mailFrom, '250')) {
            fclose($socket);
            return ['success' => false, 'error' => 'MAIL FROM rejected'];
        }

        // RCPT TO
        $this->sendCommand($socket, "RCPT TO:<$to>");
        $rcptTo = $this->readResponse($socket);
        if (!str_starts_with($rcptTo, '250')) {
            fclose($socket);
            return ['success' => false, 'error' => 'Recipient rejected'];
        }

        // DATA
        $this->sendCommand($socket, "DATA");
        $data = $this->readResponse($socket);
        if (!str_starts_with($data, '354')) {
            fclose($socket);
            return ['success' => false, 'error' => 'DATA rejected'];
        }

        // Build message
        $messageId = bin2hex(random_bytes(16)) . '@' . parse_url("https://$host", PHP_URL_HOST);
        $date = gmdate('r');

        $headers = [
            "Message-ID: <$messageId>",
            "Date: $date",
            "From: " . ($fromName ? "\"$fromName\" <$fromEmail>" : $fromEmail),
            "To: $to",
            "Subject: $subject",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=UTF-8",
            "X-PRF-KeyId: " . substr($keyId, 0, 20) . "..."
        ];

        if ($replyTo !== null && filter_var($replyTo, FILTER_VALIDATE_EMAIL)) {
            $headers[] = "Reply-To: $replyTo";
        }

        // Dot-stuff the body per RFC 5321: lines starting with "." get an extra "."
        $stuffedBody = implode("\r\n", array_map(function ($line) {
            return str_starts_with($line, '.') ? '.' . $line : $line;
        }, explode("\n", str_replace("\r\n", "\n", $body))));

        $message = implode("\r\n", $headers) . "\r\n\r\n" . $stuffedBody . "\r\n.";
        fwrite($socket, $message . "\r\n");

        $sent = $this->readResponse($socket);
        if (!str_starts_with($sent, '250')) {
            fclose($socket);
            return ['success' => false, 'error' => 'Send failed'];
        }

        // QUIT
        $this->sendCommand($socket, "QUIT");
        fclose($socket);

        return [
            'success' => true,
            'messageId' => $messageId,
            'sentAt' => gmdate('c')
        ];
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
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }
        return trim($response);
    }

    /**
     * Check if an IP address is private/reserved (SSRF protection).
     */
    private function isPrivateIp(string $ip): bool
    {
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }
}
