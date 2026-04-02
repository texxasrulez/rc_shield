<?php

class rcs_provider_generic_http implements rcs_provider_interface
{
    private rcube_config $config;

    public function __construct(rcube_config $config)
    {
        $this->config = $config;
    }

    public function get_name(): string
    {
        return 'generic_http';
    }

    public function is_enabled(): bool
    {
        return (bool) $this->config->get('rcs_enable_external_reputation', false)
            && !empty($this->config->get('rcs_http_providers', []));
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function enrich(array $context): array
    {
        $providers = (array) $this->config->get('rcs_http_providers', []);
        $allowedHosts = array_map('strtolower', (array) $this->config->get('rcs_allowed_http_hosts', []));
        $timeout = max(1, (int) $this->config->get('rcs_http_timeout', 4));
        $originIp = (string) ($context['origin_ip'] ?? '');

        $responses = [];
        $blacklistHit = false;
        $country = '';

        foreach ($providers as $provider) {
            if (!is_array($provider)) {
                continue;
            }

            $url = (string) ($provider['url'] ?? '');
            $host = strtolower((string) parse_url($url, PHP_URL_HOST));

            // Security: outbound HTTP is restricted to explicit config allowlists to prevent SSRF.
            if ($host === '' || !in_array($host, $allowedHosts, true)) {
                continue;
            }

            if (!preg_match('#^https://#i', $url)) {
                continue;
            }

            if ($originIp === '' || !rcs_helpers::ip_is_public($originIp)) {
                continue;
            }

            $query = $url . (str_contains($url, '?') ? '&' : '?') . http_build_query(['ip' => $originIp], '', '&', PHP_QUERY_RFC3986);
            $data = $this->http_get_json($query, $timeout);
            if ($data === null) {
                continue;
            }

            $responses[] = [
                'name' => (string) ($provider['name'] ?? $host),
                'response' => $data,
            ];

            if (!empty($data['blacklist_hit'])) {
                $blacklistHit = true;
            }

            if ($country === '' && !empty($data['country']) && is_string($data['country'])) {
                $country = $data['country'];
            }
        }

        return [
            'provider' => $this->get_name(),
            'blacklist_hit' => $blacklistHit,
            'country' => $country,
            'responses' => $responses,
        ];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function http_get_json(string $url, int $timeout): ?array
    {
        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init($url);
        if (!$ch) {
            return null;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_USERAGENT => 'RoundcubeShield/1.0',
        ]);

        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if (!is_string($response) || $status < 200 || $status >= 300) {
            return null;
        }

        $decoded = json_decode($response, true);
        return is_array($decoded) ? $decoded : null;
    }
}
