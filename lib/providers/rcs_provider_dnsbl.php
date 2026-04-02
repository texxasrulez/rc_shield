<?php

class rcs_provider_dnsbl implements rcs_provider_interface
{
    private rcube_config $config;
    private rcs_dns $dns;

    public function __construct(rcube_config $config, rcs_dns $dns)
    {
        $this->config = $config;
        $this->dns = $dns;
    }

    public function get_name(): string
    {
        return 'dnsbl';
    }

    public function is_enabled(): bool
    {
        return !empty($this->config->get('rcs_dnsbl_providers', []));
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function enrich(array $context): array
    {
        $ip = (string) ($context['origin_ip'] ?? '');
        $zones = (array) $this->config->get('rcs_dnsbl_providers', []);
        $hits = $ip !== '' ? $this->dns->query_dnsbl($ip, $zones) : [];

        return [
            'provider' => $this->get_name(),
            'blacklist_hit' => !empty($hits),
            'hits' => $hits,
        ];
    }
}
