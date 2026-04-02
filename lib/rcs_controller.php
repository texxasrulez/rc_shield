<?php

class rcs_controller
{
    private rcmail $rcmail;
    private rcube_plugin $plugin;
    private rcs_storage $storage;
    private rcs_analyzer $analyzer;
    private rcs_cache $cache;
    private rcube_config $config;

    public function __construct(
        rcmail $rcmail,
        rcube_plugin $plugin,
        rcs_storage $storage,
        rcs_analyzer $analyzer,
        rcs_cache $cache,
        rcube_config $config
    ) {
        $this->rcmail = $rcmail;
        $this->plugin = $plugin;
        $this->storage = $storage;
        $this->analyzer = $analyzer;
        $this->cache = $cache;
        $this->config = $config;
    }

    public function action_statuses(): void
    {
        $this->assert_mail_request();
        $mailbox = rcs_helpers::sanitize_mailbox((string) rcube_utils::get_input_value('_mbox', rcube_utils::INPUT_POST));
        $limit = (int) $this->config->get('rcs_mailbox_batch_limit', 200);
        $uids = rcs_helpers::sanitize_uid_list(rcube_utils::get_input_value('_uids', rcube_utils::INPUT_POST), $limit);

        if ($mailbox === '' || empty($uids)) {
            rcs_helpers::debug_log($this->config, 'statuses_invalid_request', ['mailbox' => $mailbox, 'uids' => $uids]);
            $this->json(['ok' => false, 'error' => 'invalid_request'], 400);
        }

        $payload = [];

        foreach ($uids as $uid) {
            $context = $this->storage->load_message_context($uid, $mailbox);
            if ($context === null) {
                $payload[$uid] = [
                    'level' => 'unknown',
                    'score' => 0,
                    'label' => 'Unknown',
                    'tooltip' => 'Message analysis unavailable',
                ];
                continue;
            }

            $analysis = $this->analyzer->analyze($context);
            $payload[$uid] = [
                'level' => (string) ($analysis['status']['level'] ?? 'unknown'),
                'score' => (int) ($analysis['status']['score'] ?? 0),
                'label' => (string) ($analysis['status']['label'] ?? 'Unknown'),
                'tooltip' => (string) ($analysis['score']['summary'] ?? 'Message analysis unavailable'),
            ];
        }

        $this->json(['ok' => true, 'statuses' => $payload]);
    }

    public function action_analysis(): void
    {
        $this->assert_mail_request();
        $mailbox = rcs_helpers::sanitize_mailbox((string) rcube_utils::get_input_value('_mbox', rcube_utils::INPUT_GPC));
        $uid = rcs_helpers::sanitize_uid(rcube_utils::get_input_value('_uid', rcube_utils::INPUT_GPC));

        if ($mailbox === '' || $uid <= 0) {
            rcs_helpers::debug_log($this->config, 'analysis_invalid_request', ['mailbox' => $mailbox, 'uid' => $uid]);
            $this->json(['ok' => false, 'error' => 'invalid_request'], 400);
        }

        $context = $this->storage->load_message_context($uid, $mailbox);
        if ($context === null) {
            rcs_helpers::debug_log($this->config, 'analysis_message_not_found', ['mailbox' => $mailbox, 'uid' => $uid]);
            $this->json(['ok' => false, 'error' => 'message_not_found'], 404);
        }

        $analysis = $this->analyzer->analyze($context);
        $this->json(['ok' => true, 'analysis' => $this->build_response($analysis)]);
    }

    public function action_purge_cache(): void
    {
        $this->assert_mail_request();
        if (!$this->is_admin()) {
            rcs_helpers::debug_log($this->config, 'cache_purge_forbidden');
            $this->json(['ok' => false, 'error' => 'forbidden'], 403);
        }

        $this->cache->purge_scope('analysis');
        $this->cache->purge_scope('reputation');
        $this->cache->purge_scope('headers');
        $this->cache->purge_expired();

        $this->json(['ok' => true, 'message' => $this->plugin->gettext('cache_purged')]);
    }

    private function assert_mail_request(): void
    {
        $token = rcs_helpers::sanitize_token((string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_GPC));
        if ($token === '' && !empty($_SERVER['HTTP_X_RCUBE_TOKEN'])) {
            $token = rcs_helpers::sanitize_token((string) $_SERVER['HTTP_X_RCUBE_TOKEN']);
        }

        $expected = method_exists($this->rcmail, 'get_request_token') ? (string) $this->rcmail->get_request_token() : '';
        if ($expected === '' || $token === '' || !hash_equals($expected, $token)) {
            rcs_helpers::debug_log($this->config, 'csrf_failure');
            $this->json(['ok' => false, 'error' => 'csrf'], 403);
        }
    }

    private function is_admin(): bool
    {
        $admins = array_map('intval', (array) $this->config->get('rcs_admin_user_ids', []));
        $userId = method_exists($this->rcmail, 'get_user_id') ? (int) $this->rcmail->get_user_id() : 0;

        return in_array($userId, $admins, true);
    }

    /**
     * @param array<string, mixed> $analysis
     * @return array<string, mixed>
     */
    private function build_response(array $analysis): array
    {
        $normalized = (array) ($analysis['normalized'] ?? []);
        $reputation = (array) ($analysis['reputation'] ?? []);
        $score = (array) ($analysis['score'] ?? []);

        $fromDomain = (string) ($normalized['from']['domain'] ?? '');
        $replyDomain = (string) ($normalized['reply_to']['domain'] ?? '');
        $returnDomain = (string) ($normalized['return_path']['domain'] ?? '');

        return [
            'uid' => (int) ($analysis['uid'] ?? 0),
            'status' => $analysis['status'] ?? [],
            'score' => $score,
            'summary' => (string) ($score['summary'] ?? ''),
            'authentication' => [
                'spf' => $normalized['spf'] ?? [],
                'dkim' => $normalized['dkim'] ?? [],
                'dmarc' => $normalized['dmarc'] ?? [],
            ],
            'domains' => [
                'from' => $fromDomain,
                'reply_to' => $replyDomain,
                'return_path' => $returnDomain,
                'reply_to_mismatch' => $fromDomain !== '' && $replyDomain !== '' && !rcs_helpers::domains_match($fromDomain, $replyDomain),
                'return_path_mismatch' => $fromDomain !== '' && $returnDomain !== '' && !rcs_helpers::domains_match($fromDomain, $returnDomain),
            ],
            'origin' => [
                'ip' => (string) ($normalized['origin_ip'] ?? ''),
                'rdns' => (string) ($reputation['rdns'] ?? $normalized['rdns'] ?? ''),
                'country' => (string) ($reputation['country'] ?? ''),
            ],
            'reputation' => [
                'summary' => !empty($reputation['blacklist_hit'])
                    ? 'Configured reputation source reported a blacklist hit'
                    : 'No configured provider reported a blacklist hit',
                'provider_data' => $reputation['provider_data'] ?? [],
            ],
            'reasons' => $score['reasons'] ?? [],
            'technical' => [
                'received_chain' => $normalized['received_chain'] ?? [],
                'warnings' => $normalized['warnings'] ?? [],
                'x_headers' => $normalized['x_headers'] ?? [],
                'message_id' => $normalized['message_id'] ?? '',
                'helo' => $normalized['helo'] ?? '',
            ],
        ];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function json(array $payload, int $status = 200): void
    {
        header('Content-Type: application/json; charset=UTF-8', true, $status);
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }
}
