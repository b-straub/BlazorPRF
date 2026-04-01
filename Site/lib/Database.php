<?php

namespace Lib;

use SQLite3;

class Database
{
    private SQLite3 $db;

    public function __construct(string $path)
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $this->db = new SQLite3($path);
        $this->db->enableExceptions(true);
        $this->initSchema();
    }

    public function initSchema(): void
    {
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS public_keys (
                key_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                user_id TEXT,
                created INTEGER NOT NULL,
                revoked_at INTEGER DEFAULT NULL
            )
        ');

        $this->db->exec('
            CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                created INTEGER NOT NULL
            )
        ');

        $this->db->exec('
            CREATE INDEX IF NOT EXISTS idx_nonces_created ON nonces(created)
        ');
    }

    public function getPublicKey(string $keyId): ?string
    {
        $stmt = $this->db->prepare('
            SELECT public_key FROM public_keys
            WHERE key_id = :key_id AND revoked_at IS NULL
        ');
        $stmt->bindValue(':key_id', $keyId, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);

        return $row ? $row['public_key'] : null;
    }

    public function storePublicKey(string $keyId, string $publicKey, string $userId): void
    {
        $stmt = $this->db->prepare('
            INSERT OR REPLACE INTO public_keys (key_id, public_key, user_id, created)
            VALUES (:key_id, :public_key, :user_id, :created)
        ');
        $stmt->bindValue(':key_id', $keyId, SQLITE3_TEXT);
        $stmt->bindValue(':public_key', $publicKey, SQLITE3_TEXT);
        $stmt->bindValue(':user_id', $userId, SQLITE3_TEXT);
        $stmt->bindValue(':created', time(), SQLITE3_INTEGER);
        $stmt->execute();
    }

    public function revokePublicKey(string $keyId): bool
    {
        $stmt = $this->db->prepare('
            UPDATE public_keys SET revoked_at = :revoked_at WHERE key_id = :key_id
        ');
        $stmt->bindValue(':key_id', $keyId, SQLITE3_TEXT);
        $stmt->bindValue(':revoked_at', time(), SQLITE3_INTEGER);
        $stmt->execute();

        return $this->db->changes() > 0;
    }

    public function isNonceUsed(string $nonce): bool
    {
        $stmt = $this->db->prepare('SELECT 1 FROM nonces WHERE nonce = :nonce');
        $stmt->bindValue(':nonce', $nonce, SQLITE3_TEXT);
        $result = $stmt->execute();

        return $result->fetchArray() !== false;
    }

    /**
     * Atomically store a nonce. Returns false if nonce already exists (race condition safe).
     */
    public function storeNonceAtomic(string $nonce, int $timestamp): bool
    {
        $stmt = $this->db->prepare('INSERT OR IGNORE INTO nonces (nonce, created) VALUES (:nonce, :created)');
        $stmt->bindValue(':nonce', $nonce, SQLITE3_TEXT);
        $stmt->bindValue(':created', $timestamp, SQLITE3_INTEGER);
        $stmt->execute();

        return $this->db->changes() > 0;
    }

    public function cleanExpiredNonces(int $maxAge = 300): int
    {
        $cutoff = time() - $maxAge;
        $stmt = $this->db->prepare('DELETE FROM nonces WHERE created < :cutoff');
        $stmt->bindValue(':cutoff', $cutoff, SQLITE3_INTEGER);
        $stmt->execute();

        return $this->db->changes();
    }

    public function listPublicKeys(bool $includeRevoked = false): array
    {
        $sql = '
            SELECT key_id AS keyId, public_key AS publicKey, user_id AS userId,
                   created AS createdAt, revoked_at AS revokedAt
            FROM public_keys
        ';

        if (!$includeRevoked) {
            $sql .= ' WHERE revoked_at IS NULL';
        }

        $sql .= ' ORDER BY created DESC';

        $result = $this->db->query($sql);

        $keys = [];
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            $keys[] = $row;
        }

        return $keys;
    }
}
