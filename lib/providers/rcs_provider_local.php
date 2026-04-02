<?php

class rcs_provider_local implements rcs_provider_interface
{
    private rcube_config $config;
    private rcs_dns $dns;
    private rcs_geo $geo;

    public function __construct(rcube_config $config, rcs_dns $dns, rcs_geo $geo)
    {
        $this->config = $config;
        $this->dns = $dns;
        $this->geo = $geo;
    }

    public function get_name(): string
    {
        return 'local';
    }

    public function is_enabled(): bool
    {
        return true;
    }

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function enrich(array $context): array
    {
        $originIp = (string) ($context['origin_ip'] ?? '');
        $fromDomain = (string) ($context['from']['domain'] ?? '');
        $fromEmail = (string) ($context['from']['email'] ?? '');

        $dnsData = $originIp !== '' && (bool) $this->config->get('rcs_enable_dns', true)
            ? $this->dns->lookup($originIp)
            : ['ip' => $originIp, 'is_valid' => false, 'is_public' => false, 'is_private_or_reserved' => false, 'rdns' => ''];

        $geoData = (bool) $this->config->get('rcs_enable_geo', true)
            ? $this->geo->locate($context)
            : ['country' => '', 'source' => 'disabled'];

        $allowlistedDomains = array_map('strtolower', (array) $this->config->get('rcs_allowlisted_domains', []));
        $allowlistedEmails = array_map('strtolower', (array) $this->config->get('rcs_allowlisted_emails', []));
        $blocklistedDomains = array_map('strtolower', (array) $this->config->get('rcs_blocklisted_domains', []));
        $blocklistedIps = (array) $this->config->get('rcs_blocklisted_ips', []);
        $trustedNetworks = (array) $this->config->get('rcs_trusted_mta_networks', []);

        return [
            'provider' => $this->get_name(),
            'rdns' => (string) ($dnsData['rdns'] ?? ''),
            'country' => (string) ($geoData['country'] ?? ''),
            'ip_is_private_or_reserved' => (bool) ($dnsData['is_private_or_reserved'] ?? false),
            'trusted_sender' => in_array($fromDomain, $allowlistedDomains, true) || in_array($fromEmail, $allowlistedEmails, true),
            'trusted_network' => $originIp !== '' && rcs_helpers::match_ip_ranges($originIp, $trustedNetworks),
            'blacklist_hit' => ($fromDomain !== '' && in_array($fromDomain, $blocklistedDomains, true))
                || ($originIp !== '' && rcs_helpers::match_ip_ranges($originIp, $blocklistedIps)),
            'details' => [
                'dns' => $dnsData,
                'geo' => $geoData,
            ],
        ];
    }
}
