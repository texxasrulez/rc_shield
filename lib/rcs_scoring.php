<?php

class rcs_scoring
{
    private rcube_config $config;

    public function __construct(rcube_config $config)
    {
        $this->config = $config;
    }

    /**
     * @param array<string, mixed> $normalized
     * @param array<string, mixed> $reputation
     * @return array<string, mixed>
     */
    public function score(array $normalized, array $reputation): array
    {
        $score = 0;
        $reasons = [];

        $this->add_auth_reason($score, $reasons, 'spf', (string) ($normalized['spf']['result'] ?? 'none'));
        $this->add_auth_reason($score, $reasons, 'dkim', (string) ($normalized['dkim']['result'] ?? 'none'));
        $this->add_auth_reason($score, $reasons, 'dmarc', (string) ($normalized['dmarc']['result'] ?? 'none'));

        $fromDomain = (string) ($normalized['from']['domain'] ?? '');
        $replyDomain = (string) ($normalized['reply_to']['domain'] ?? '');
        $returnDomain = (string) ($normalized['return_path']['domain'] ?? '');
        $originIp = (string) ($normalized['origin_ip'] ?? '');
        $helo = (string) ($normalized['helo'] ?? '');

        if ($fromDomain !== '' && $replyDomain !== '' && !rcs_helpers::domains_match($fromDomain, $replyDomain)) {
            $this->add_reason($score, $reasons, 'replyto_mismatch', (int) $this->config->get('rcs_weight_replyto_mismatch', 20), 'Reply-To domain differs from From domain');
        }

        if ($fromDomain !== '' && $returnDomain !== '' && !rcs_helpers::domains_match($fromDomain, $returnDomain)) {
            $this->add_reason($score, $reasons, 'returnpath_mismatch', (int) $this->config->get('rcs_weight_returnpath_mismatch', 15), 'Return-Path domain differs from From domain');
        }

        if ($helo !== '' && preg_match('/(?:localhost|localdomain|\[?127\.|dynamic|unknown)/i', $helo)) {
            $this->add_reason($score, $reasons, 'suspicious_helo', (int) $this->config->get('rcs_weight_suspicious_helo', 12), 'HELO/EHLO identity appears suspicious');
        }

        if ($originIp !== '' && empty($reputation['rdns'])) {
            $this->add_reason($score, $reasons, 'no_rdns', (int) $this->config->get('rcs_weight_no_rdns', 10), 'No reverse DNS name was resolved for the origin IP');
        }

        if (!empty($reputation['blacklist_hit'])) {
            $this->add_reason($score, $reasons, 'blacklist_hit', (int) $this->config->get('rcs_weight_blacklist_hit', 35), 'Origin or sender matched a configured reputation blocklist');
        }

        if ($originIp !== '' && rcs_helpers::ip_is_private_or_reserved($originIp)) {
            $this->add_reason($score, $reasons, 'private_origin_ip', (int) $this->config->get('rcs_weight_private_origin_ip', 5), 'Origin IP is private or reserved');
        }

        if (!empty($normalized['warnings'])) {
            $this->add_reason($score, $reasons, 'malformed_headers', (int) $this->config->get('rcs_weight_malformed_headers', 10), 'One or more important headers were missing or malformed');
        }

        if (!empty($reputation['trusted_sender'])) {
            $this->add_reason($score, $reasons, 'trusted_sender', (int) $this->config->get('rcs_weight_trusted_sender_deduction', -20), 'Sender matched a configured allowlist');
        }

        if (!empty($reputation['trusted_network'])) {
            $this->add_reason($score, $reasons, 'trusted_network', (int) $this->config->get('rcs_weight_trusted_network_deduction', -15), 'Origin IP matched a configured trusted network');
        }

        $score = max(0, $score);
        $safeMax = (int) $this->config->get('rcs_score_threshold_safe_max', 30);
        $suspiciousMax = (int) $this->config->get('rcs_score_threshold_suspicious_max', 70);

        if ($score <= $safeMax) {
            $level = 'safe';
            $summary = 'Authentication and header indicators are consistent with a low-risk message.';
        } elseif ($score <= $suspiciousMax) {
            $level = 'suspicious';
            $summary = 'The message has mixed or incomplete trust signals and should be reviewed carefully.';
        } else {
            $level = 'danger';
            $summary = 'Multiple high-risk indicators suggest the message may be forged or abusive.';
        }

        if (empty($reasons)) {
            $level = 'unknown';
            $summary = 'Not enough trustworthy header intelligence was available to produce a confident result.';
        }

        return [
            'score' => $score,
            'level' => $level,
            'reasons' => $reasons,
            'summary' => $summary,
        ];
    }

    /**
     * @param array<int, array<string, mixed>> $reasons
     */
    private function add_auth_reason(int &$score, array &$reasons, string $method, string $result): void
    {
        $result = rcs_helpers::normalize_result($result);
        $map = [
            'spf' => [
                'fail' => ['cfg' => 'rcs_weight_spf_fail', 'msg' => 'SPF validation failed'],
                'softfail' => ['cfg' => 'rcs_weight_spf_softfail', 'msg' => 'SPF returned softfail'],
                'none' => ['cfg' => 'rcs_weight_spf_none', 'msg' => 'SPF data was missing'],
            ],
            'dkim' => [
                'fail' => ['cfg' => 'rcs_weight_dkim_fail', 'msg' => 'DKIM validation failed'],
                'none' => ['cfg' => 'rcs_weight_dkim_none', 'msg' => 'No DKIM result was available'],
            ],
            'dmarc' => [
                'fail' => ['cfg' => 'rcs_weight_dmarc_fail', 'msg' => 'DMARC validation failed'],
                'none' => ['cfg' => 'rcs_weight_dmarc_none', 'msg' => 'No DMARC result was available'],
            ],
        ];

        if (!isset($map[$method][$result])) {
            return;
        }

        $meta = $map[$method][$result];
        $this->add_reason($score, $reasons, $method . '_' . $result, (int) $this->config->get($meta['cfg'], 0), $meta['msg']);
    }

    /**
     * @param array<int, array<string, mixed>> $reasons
     */
    private function add_reason(int &$score, array &$reasons, string $code, int $points, string $message): void
    {
        if ($points === 0) {
            return;
        }

        $score += $points;
        $reasons[] = [
            'code' => $code,
            'points' => $points,
            'message' => $message,
        ];
    }
}
