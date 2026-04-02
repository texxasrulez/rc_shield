<?php

class rcs_cache
{
    private rcube_db $db;
    private rcube_config $config;

    public function __construct(rcube_db $db, rcube_config $config)
    {
        $this->db = $db;
        $this->config = $config;
    }

    public function build_key(string $scope, array $parts): string
    {
        return sha1($scope . '|' . rcs_helpers::safe_json($parts));
    }

    /**
     * @return array<string, mixed>|null
     */
    public function get(string $scope, string $key): ?array
    {
        $sql = 'SELECT payload, expires_at FROM rcs_cache WHERE cache_key = ? AND cache_scope = ?';
        $result = $this->db->query($sql, $key, $scope);
        $row = $this->db->fetch_assoc($result);

        if (!$row) {
            rcs_helpers::debug_log($this->config, 'cache_miss', ['scope' => $scope, 'key' => $key]);
            return null;
        }

        if ((int) ($row['expires_at'] ?? 0) < time()) {
            $this->delete($scope, $key);
            rcs_helpers::debug_log($this->config, 'cache_expired', ['scope' => $scope, 'key' => $key]);
            return null;
        }

        $payload = json_decode((string) $row['payload'], true);
        rcs_helpers::debug_log($this->config, 'cache_hit', ['scope' => $scope, 'key' => $key]);
        return is_array($payload) ? $payload : null;
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function set(string $scope, string $key, array $payload, int $ttl, array $meta = []): void
    {
        $now = time();
        $expires = $now + max(60, $ttl);
        $mailbox = (string) ($meta['mailbox'] ?? '');
        $messageUid = (int) ($meta['message_uid'] ?? 0);
        $identityHash = (string) ($meta['identity_hash'] ?? '');
        $userId = (int) ($meta['user_id'] ?? 0);
        $payloadJson = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        [$sql, $params] = $this->build_upsert_query(
            $key,
            $scope,
            $userId,
            $mailbox,
            $messageUid,
            $identityHash,
            (string) $payloadJson,
            $expires,
            $now
        );

        $this->db->query(
            $sql,
            ...$params
        );
        rcs_helpers::debug_log($this->config, 'cache_set', ['scope' => $scope, 'key' => $key, 'ttl' => $ttl]);
    }

    public function delete(string $scope, string $key): void
    {
        $this->db->query('DELETE FROM rcs_cache WHERE cache_key = ? AND cache_scope = ?', $key, $scope);
    }

    public function purge_scope(string $scope): void
    {
        $this->db->query('DELETE FROM rcs_cache WHERE cache_scope = ?', $scope);
        rcs_helpers::debug_log($this->config, 'cache_purge_scope', ['scope' => $scope]);
    }

    public function purge_expired(): void
    {
        $this->db->query('DELETE FROM rcs_cache WHERE expires_at < ?', time());
        rcs_helpers::debug_log($this->config, 'cache_purge_expired');
    }

    /**
     * @return array{0: string, 1: array<int, int|string>}
     */
    private function build_upsert_query(
        string $key,
        string $scope,
        int $userId,
        string $mailbox,
        int $messageUid,
        string $identityHash,
        string $payload,
        int $expires,
        int $now
    ): array {
        $params = [
            $key,
            $scope,
            $userId,
            $mailbox,
            $messageUid,
            $identityHash,
            $payload,
            $expires,
            $now,
        ];
        $driver = $this->get_db_driver();

        if ($driver === 'mysql') {
            return [
                'INSERT INTO rcs_cache (cache_key, cache_scope, user_id, mailbox, message_uid, identity_hash, payload, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    cache_scope = VALUES(cache_scope),
                    user_id = VALUES(user_id),
                    mailbox = VALUES(mailbox),
                    message_uid = VALUES(message_uid),
                    identity_hash = VALUES(identity_hash),
                    payload = VALUES(payload),
                    expires_at = VALUES(expires_at),
                    updated_at = VALUES(updated_at)',
                $params,
            ];
        }

        if ($driver === 'pgsql' || $driver === 'sqlite') {
            return [
                'INSERT INTO rcs_cache (cache_key, cache_scope, user_id, mailbox, message_uid, identity_hash, payload, expires_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (cache_key) DO UPDATE SET
                    cache_scope = excluded.cache_scope,
                    user_id = excluded.user_id,
                    mailbox = excluded.mailbox,
                    message_uid = excluded.message_uid,
                    identity_hash = excluded.identity_hash,
                    payload = excluded.payload,
                    expires_at = excluded.expires_at,
                    updated_at = excluded.updated_at',
                $params,
            ];
        }

        return [
            'UPDATE rcs_cache
                SET cache_scope = ?, user_id = ?, mailbox = ?, message_uid = ?, identity_hash = ?, payload = ?, expires_at = ?, updated_at = ?
                WHERE cache_key = ?',
            [
                $scope,
                $userId,
                $mailbox,
                $messageUid,
                $identityHash,
                $payload,
                $expires,
                $now,
                $key,
            ],
        ];
    }

    private function get_db_driver(): string
    {
        $dsn = strtolower((string) $this->config->get('db_dsnw', ''));

        if (preg_match('/^(mysql|mysqli|pgsql|postgres|sqlite)(:|:\/\/)/', $dsn, $matches)) {
            return match ($matches[1]) {
                'mysqli' => 'mysql',
                'postgres' => 'pgsql',
                default => $matches[1],
            };
        }

        return '';
    }
}
