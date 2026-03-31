<?php

namespace Actions;

/**
 * IMAP connection and email fetching with body extraction.
 */
class TestImap
{
    /**
     * Execute the IMAP action.
     *
     * @param array $params Expected: imapHost, imapPort, imapUsername, imapPassword,
     *                      filter (optional), since (optional), limit (optional),
     *                      fetchBody (optional), uid (optional for single email)
     * @param string $keyId The authenticated key ID
     * @return array Result with success status and optionally email list
     */
    public function execute(array $params, string $keyId): array
    {
        $host = $params['imapHost'] ?? '';
        $port = (int)($params['imapPort'] ?? 993);
        $username = $params['imapUsername'] ?? '';
        $password = $params['imapPassword'] ?? '';
        $folder = $params['folder'] ?? 'INBOX';
        $filter = $params['filter'] ?? 'test'; // test, all, unseen, new, since
        $since = $params['since'] ?? null; // Unix timestamp or date string
        $limit = min((int)($params['limit'] ?? 10), 50); // Max 50
        $fetchBody = (bool)($params['fetchBody'] ?? false);
        $singleUid = isset($params['uid']) ? (int)$params['uid'] : null;

        if (empty($host)) {
            return ['success' => false, 'error' => 'IMAP host is required'];
        }

        if (empty($username)) {
            return ['success' => false, 'error' => 'IMAP username is required'];
        }

        if (empty($password)) {
            return ['success' => false, 'error' => 'IMAP password is required'];
        }

        // Block SSRF via private/reserved IP ranges
        $resolvedIp = gethostbyname($host);
        if (!filter_var($resolvedIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return ['success' => false, 'error' => 'IMAP host resolves to a private/reserved IP address'];
        }

        // Sanitize folder name (prevent IMAP connection string injection)
        if (!preg_match('/^[a-zA-Z0-9._\-\/]+$/', $folder)) {
            return ['success' => false, 'error' => 'Invalid folder name'];
        }

        // Build connection string
        // Common ports: 993 (SSL), 143 (plain/STARTTLS)
        $ssl = $port === 993 ? '/ssl' : '';
        $connectionString = "{{$host}:{$port}/imap{$ssl}}$folder";

        try {
            // Suppress warnings, we'll handle errors ourselves
            $connection = @imap_open($connectionString, $username, $password, 0, 1);

            if ($connection === false) {
                return [
                    'success' => false,
                    'error' => 'IMAP connection failed'
                ];
            }

            // Connection successful
            $result = [
                'success' => true,
                'message' => 'IMAP connection successful',
                'host' => $host,
                'port' => $port,
                'folder' => $folder
            ];

            // Handle single email fetch by UID (check this FIRST before filter)
            if ($singleUid !== null) {
                $email = $this->fetchSingleEmail($connection, $singleUid, true);
                if ($email === null) {
                    imap_close($connection);
                    return ['success' => false, 'error' => 'Email not found'];
                }
                $result['email'] = $email;
                imap_close($connection);
                return $result;
            }

            // If just testing connection, return now
            if ($filter === 'test') {
                $mailboxInfo = imap_check($connection);
                if ($mailboxInfo) {
                    $result['mailbox'] = [
                        'messages' => $mailboxInfo->Nmsgs,
                        'recent' => $mailboxInfo->Recent,
                        'unseen' => $mailboxInfo->Unseen ?? 0
                    ];
                }
                imap_close($connection);
                return $result;
            }

            // Build search criteria
            $criteria = $this->buildSearchCriteria($filter, $since);

            // Search for messages
            $messageIds = @imap_search($connection, $criteria, SE_UID);

            if ($messageIds === false) {
                $result['emails'] = [];
                $result['count'] = 0;
                imap_close($connection);
                return $result;
            }

            // Sort by UID descending (newest first)
            rsort($messageIds);

            // Limit results
            $messageIds = array_slice($messageIds, 0, $limit);

            // Fetch emails
            $emails = [];
            foreach ($messageIds as $uid) {
                $email = $this->fetchSingleEmail($connection, $uid, $fetchBody);
                if ($email !== null) {
                    $emails[] = $email;
                }
            }

            $result['emails'] = $emails;
            $result['count'] = count($emails);
            $result['totalMatched'] = count($messageIds);
            $result['filter'] = $filter;
            $result['criteria'] = $criteria;

            imap_close($connection);
            return $result;

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => 'IMAP error'
            ];
        }
    }

    /**
     * Fetch a single email with optional body.
     */
    private function fetchSingleEmail($connection, int $uid, bool $includeBody): ?array
    {
        $msgNo = @imap_msgno($connection, $uid);
        if ($msgNo === 0) {
            return null;
        }

        $headerInfo = @imap_headerinfo($connection, $msgNo);
        if ($headerInfo === false) {
            return null;
        }

        $email = [
            'uid' => $uid,
            'subject' => $this->decodeHeader($headerInfo->subject ?? ''),
            'from' => $this->formatAddress($headerInfo->from ?? []),
            'to' => $this->formatAddress($headerInfo->to ?? []),
            'date' => $headerInfo->date ?? '',
            'timestamp' => strtotime($headerInfo->date ?? 'now'),
            'seen' => ($headerInfo->Unseen ?? 'U') !== 'U',
            'flagged' => ($headerInfo->Flagged ?? ' ') === 'F',
            'size' => $headerInfo->Size ?? 0
        ];

        if ($includeBody) {
            $body = $this->getEmailBody($connection, $uid);
            $email['body'] = $body['text'];
            $email['bodyHtml'] = $body['html'];
            $email['hasPfaArmor'] = $this->containsPfaArmor($body['text']);
        }

        return $email;
    }

    /**
     * Get email body (plain text and HTML).
     */
    private function getEmailBody($connection, int $uid): array
    {
        $structure = @imap_fetchstructure($connection, $uid, FT_UID);
        if ($structure === false) {
            return ['text' => '', 'html' => ''];
        }

        $text = '';
        $html = '';

        if (empty($structure->parts)) {
            // Simple message (no parts) - use empty string for section
            $body = @imap_body($connection, $uid, FT_UID);
            $decoded = $this->decodeBody($body, $structure->encoding ?? 0);
            $charset = $this->getCharset($structure);
            $decoded = $this->convertToUtf8($decoded, $charset);

            if (isset($structure->subtype) && strtoupper($structure->subtype) === 'HTML') {
                $html = $decoded;
            } else {
                $text = $decoded;
            }
        } else {
            // Multipart message
            $this->extractParts($connection, $uid, $structure->parts, '', $text, $html);
        }

        return ['text' => $text, 'html' => $html];
    }

    /**
     * Recursively extract text and HTML parts from message structure.
     */
    private function extractParts($connection, int $uid, array $parts, string $partNum, string &$text, string &$html): void
    {
        foreach ($parts as $index => $part) {
            $currentPartNum = $partNum ? "$partNum." . ($index + 1) : (string)($index + 1);

            if (isset($part->parts) && !empty($part->parts)) {
                // Nested multipart
                $this->extractParts($connection, $uid, $part->parts, $currentPartNum, $text, $html);
            } else {
                $subtype = strtoupper($part->subtype ?? '');
                $type = $part->type ?? 0;

                // Only process text types
                if ($type === 0) { // TYPETEXT
                    $body = @imap_fetchbody($connection, $uid, $currentPartNum, FT_UID);
                    $decoded = $this->decodeBody($body, $part->encoding ?? 0);
                    $charset = $this->getCharset($part);
                    $decoded = $this->convertToUtf8($decoded, $charset);

                    if ($subtype === 'HTML') {
                        if (empty($html)) {
                            $html = $decoded;
                        }
                    } elseif ($subtype === 'PLAIN') {
                        if (empty($text)) {
                            $text = $decoded;
                        }
                    }
                }
            }
        }
    }

    /**
     * Decode body based on encoding type.
     */
    private function decodeBody(string $body, int $encoding): string
    {
        switch ($encoding) {
            case 3: // BASE64
                return base64_decode($body);
            case 4: // QUOTED-PRINTABLE
                return quoted_printable_decode($body);
            default:
                return $body;
        }
    }

    /**
     * Get charset from part parameters.
     */
    private function getCharset($part): string
    {
        if (isset($part->parameters)) {
            foreach ($part->parameters as $param) {
                if (strtoupper($param->attribute) === 'CHARSET') {
                    return $param->value;
                }
            }
        }
        return 'UTF-8';
    }

    /**
     * Convert text to UTF-8.
     */
    private function convertToUtf8(string $text, string $charset): string
    {
        if (strtoupper($charset) === 'UTF-8') {
            return $text;
        }
        $converted = @iconv($charset, 'UTF-8//IGNORE', $text);
        return $converted !== false ? $converted : $text;
    }

    /**
     * Check if text contains PFA armor markers.
     */
    private function containsPfaArmor(string $text): bool
    {
        return strpos($text, '-----BEGIN PFA MESSAGE-----') !== false;
    }

    /**
     * Build IMAP search criteria string.
     */
    private function buildSearchCriteria(string $filter, ?string $since): string
    {
        switch ($filter) {
            case 'all':
                return 'ALL';

            case 'unseen':
            case 'unread':
                return 'UNSEEN';

            case 'new':
                return 'NEW'; // Recent and unseen

            case 'recent':
                return 'RECENT';

            case 'flagged':
            case 'starred':
                return 'FLAGGED';

            case 'since':
                if ($since) {
                    // Convert timestamp to IMAP date format
                    $date = is_numeric($since)
                        ? date('j-M-Y', (int)$since)
                        : date('j-M-Y', strtotime($since));
                    return "SINCE \"$date\"";
                }
                // Default to last 7 days
                $date = date('j-M-Y', strtotime('-7 days'));
                return "SINCE \"$date\"";

            case 'today':
                $date = date('j-M-Y');
                return "SINCE \"$date\"";

            case 'week':
                $date = date('j-M-Y', strtotime('-7 days'));
                return "SINCE \"$date\"";

            default:
                return 'ALL';
        }
    }

    /**
     * Decode MIME-encoded header.
     */
    private function decodeHeader(string $header): string
    {
        $decoded = imap_mime_header_decode($header);
        $result = '';
        foreach ($decoded as $part) {
            $charset = $part->charset === 'default' ? 'UTF-8' : $part->charset;
            $text = $part->text;
            if ($charset !== 'UTF-8') {
                $converted = @iconv($charset, 'UTF-8//IGNORE', $text);
                if ($converted !== false) {
                    $text = $converted;
                }
            }
            $result .= $text;
        }
        return $result;
    }

    /**
     * Format email address array.
     */
    private function formatAddress(array $addresses): string
    {
        if (empty($addresses)) {
            return '';
        }

        $parts = [];
        foreach ($addresses as $addr) {
            $email = ($addr->mailbox ?? '') . '@' . ($addr->host ?? '');
            $name = $this->decodeHeader($addr->personal ?? '');
            $parts[] = $name ? "$name <$email>" : $email;
        }
        return implode(', ', $parts);
    }
}
