<?php

class rcs_analyzer
{
    private rcs_header_parser $parser;
    private rcs_reputation $reputation;
    private rcs_scoring $scoring;
    private rcs_cache $cache;
    private rcube_config $config;
    private rcube $rcube;

    public function __construct(
        rcs_header_parser $parser,
        rcs_reputation $reputation,
        rcs_scoring $scoring,
        rcs_cache $cache,
        rcube_config $config,
        rcube $rcube
    ) {
        $this->parser = $parser;
        $this->reputation = $reputation;
        $this->scoring = $scoring;
        $this->cache = $cache;
        $this->config = $config;
        $this->rcube = $rcube;
    }

    /**
     * @param array<string, mixed> $messageContext
     * @return array<string, mixed>
     */
    public function analyze(array $messageContext): array
    {
        $mailbox = (string) ($messageContext['mailbox'] ?? '');
        $uid = (int) ($messageContext['uid'] ?? 0);
        $identityHash = (string) ($messageContext['identity_hash'] ?? '');
        $userId = method_exists($this->rcube, 'get_user_id') ? (int) $this->rcube->get_user_id() : 0;

        $cacheKey = $this->cache->build_key('analysis', [
            'mailbox' => $mailbox,
            'uid' => $uid,
            'identity_hash' => $identityHash,
            'version' => (string) $this->config->get('rcs_analysis_version', '2'),
        ]);

        $cached = $this->cache->get('analysis', $cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        $headers = is_array($messageContext['headers'] ?? null) ? $messageContext['headers'] : [];
        $rawHeaders = (string) ($messageContext['raw_headers'] ?? '');

        $normalized = $this->parser->parse($headers, $rawHeaders);
        $reputation = $this->reputation->evaluate($normalized);
        $score = $this->scoring->score($normalized, $reputation);

        $analysis = [
            'uid' => $uid,
            'mailbox' => $mailbox,
            'identity_hash' => $identityHash,
            'normalized' => $normalized,
            'reputation' => $reputation,
            'score' => $score,
            'status' => [
                'level' => $score['level'],
                'score' => $score['score'],
                'label' => $this->level_label((string) $score['level']),
            ],
        ];

        rcs_helpers::debug_log($this->config, 'analysis_complete', [
            'mailbox' => $mailbox,
            'uid' => $uid,
            'level' => $analysis['status']['level'],
            'score' => $analysis['status']['score'],
        ]);

        $this->cache->set(
            'analysis',
            $cacheKey,
            $analysis,
            (int) $this->config->get('rcs_cache_ttl_analysis', 86400),
            [
                'mailbox' => $mailbox,
                'message_uid' => $uid,
                'identity_hash' => $identityHash,
                'user_id' => $userId,
            ]
        );

        return $analysis;
    }

    private function level_label(string $level): string
    {
        return match ($level) {
            'safe' => 'Safe',
            'suspicious' => 'Suspicious',
            'danger' => 'Dangerous',
            default => 'Unknown',
        };
    }
}
