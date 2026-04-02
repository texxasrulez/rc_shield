<?php

class rcs_dns
{
    /**
     * @return array<string, mixed>
     */
    public function lookup(string $ip): array
    {
        $result = [
            'ip' => $ip,
            'is_valid' => (bool) filter_var($ip, FILTER_VALIDATE_IP),
            'is_public' => false,
            'is_private_or_reserved' => true,
            'rdns' => '',
        ];

        if (!$result['is_valid']) {
            return $result;
        }

        $result['is_public'] = rcs_helpers::ip_is_public($ip);
        $result['is_private_or_reserved'] = !$result['is_public'];

        if ($result['is_public']) {
            $rdns = @gethostbyaddr($ip);
            if (is_string($rdns) && $rdns !== '' && $rdns !== $ip) {
                $result['rdns'] = strtolower($rdns);
            }
        }

        return $result;
    }

    /**
     * @return array<int, string>
     */
    public function query_dnsbl(string $ip, array $zones): array
    {
        if (!rcs_helpers::ip_is_public($ip)) {
            return [];
        }

        $hits = [];
        $reversed = implode('.', array_reverse(explode('.', $ip)));

        foreach ($zones as $zone) {
            $zone = rcs_helpers::normalize_domain((string) $zone);
            if ($zone === '') {
                continue;
            }

            $query = $reversed . '.' . $zone;
            if (@checkdnsrr($query . '.', 'A')) {
                $hits[] = $zone;
            }
        }

        return $hits;
    }
}
