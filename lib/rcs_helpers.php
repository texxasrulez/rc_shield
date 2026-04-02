<?php

final class rcs_helpers
{
    public static function normalize_header_name(string $name): string
    {
        return strtolower(trim($name));
    }

    public static function normalize_whitespace(string $value): string
    {
        return trim(preg_replace('/\s+/', ' ', str_replace(["\r", "\n", "\t"], ' ', $value)) ?? '');
    }

    public static function normalize_result(?string $value): string
    {
        $value = strtolower(trim((string) $value));
        return $value === '' ? 'none' : $value;
    }

    public static function sanitize_mailbox(?string $mailbox): string
    {
        $mailbox = trim((string) $mailbox);
        $mailbox = preg_replace('/[\x00-\x1F\x7F]/', '', $mailbox) ?? '';
        return mb_substr($mailbox, 0, 255);
    }

    public static function sanitize_token(?string $token): string
    {
        return trim((string) $token);
    }

    public static function sanitize_uid($uid): int
    {
        return max(0, (int) $uid);
    }

    /**
     * @param mixed $value
     * @return array<int, int>
     */
    public static function sanitize_uid_list($value, int $limit = 200): array
    {
        $uids = [];

        if (is_string($value)) {
            $value = preg_split('/[,\s]+/', $value, -1, PREG_SPLIT_NO_EMPTY);
        }

        if (!is_array($value)) {
            return $uids;
        }

        foreach ($value as $uid) {
            $uid = self::sanitize_uid($uid);
            if ($uid > 0) {
                $uids[$uid] = $uid;
            }
            if (count($uids) >= $limit) {
                break;
            }
        }

        return array_values($uids);
    }

    /**
     * @return array{email:string,domain:string,display:string}
     */
    public static function parse_address(?string $value): array
    {
        $value = trim((string) $value);
        if ($value === '') {
            return ['email' => '', 'domain' => '', 'display' => ''];
        }

        if (preg_match('/<([^<>@\s]+@[^<>@\s]+)>/u', $value, $matches)) {
            $email = strtolower(trim($matches[1]));
            $display = trim(str_replace($matches[0], '', $value), "\"' ");
        } elseif (preg_match('/([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63})/iu', $value, $matches)) {
            $email = strtolower(trim($matches[1]));
            $display = trim(str_replace($matches[1], '', $value), "\"' ");
        } else {
            $email = '';
            $display = trim($value, "\"' ");
        }

        return [
            'email' => $email,
            'domain' => self::domain_from_email($email),
            'display' => $display,
        ];
    }

    public static function domain_from_email(?string $email): string
    {
        $email = strtolower(trim((string) $email));
        $parts = explode('@', $email);
        if (count($parts) !== 2) {
            return '';
        }

        return self::normalize_domain($parts[1]);
    }

    public static function normalize_domain(?string $domain): string
    {
        $domain = strtolower(trim((string) $domain, " \t\n\r\0\x0B.<>[]()"));
        if ($domain === '') {
            return '';
        }

        return preg_replace('/[^a-z0-9.\-]/', '', $domain) ?? '';
    }

    public static function domains_match(string $a, string $b): bool
    {
        $a = self::normalize_domain($a);
        $b = self::normalize_domain($b);

        return $a !== '' && $b !== '' && $a === $b;
    }

    public static function ip_is_public(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    public static function ip_is_private_or_reserved(string $ip): bool
    {
        return $ip !== '' && !self::ip_is_public($ip);
    }

    public static function match_ip_ranges(string $ip, array $ranges): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        foreach ($ranges as $range) {
            $range = trim((string) $range);
            if ($range === '') {
                continue;
            }

            if (strpos($range, '/') === false && $range === $ip) {
                return true;
            }

            if (self::cidr_match($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    public static function cidr_match(string $ip, string $cidr): bool
    {
        [$subnet, $maskBits] = array_pad(explode('/', $cidr, 2), 2, null);
        $maskBits = (int) $maskBits;

        if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet, FILTER_VALIDATE_IP)) {
            return false;
        }

        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $maxBits = strlen($ipBin) * 8;
        if ($maskBits < 0 || $maskBits > $maxBits) {
            return false;
        }

        $bytes = intdiv($maskBits, 8);
        $bits = $maskBits % 8;

        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $bits)) & 0xFF);
        return ($ipBin[$bytes] & $mask) === ($subnetBin[$bytes] & $mask);
    }

    /**
     * @param array<string, string|array<int, string>> $headers
     * @return string
     */
    public static function raw_header_value(array $headers, string $name): string
    {
        $value = $headers[self::normalize_header_name($name)] ?? '';
        if (is_array($value)) {
            return implode("\n", $value);
        }

        return (string) $value;
    }

    /**
     * @param array<string, string|array<int, string>> $headers
     * @return array<int, string>
     */
    public static function raw_header_values(array $headers, string $name): array
    {
        $value = $headers[self::normalize_header_name($name)] ?? [];
        if (is_array($value)) {
            return array_values(array_map('strval', $value));
        }

        if ($value === '') {
            return [];
        }

        return [(string) $value];
    }

    public static function safe_json($value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}';
    }

    /**
     * @param array<string, mixed> $context
     */
    public static function debug_log(rcube_config $config, string $message, array $context = []): void
    {
        if (!(bool) $config->get('rcs_debug', false)) {
            return;
        }

        $line = '[' . date('c') . '] ' . $message;
        if (!empty($context)) {
            $line .= ' ' . self::safe_json($context);
        }

        rcube::write_log('rc_shield', $line);
    }
}
