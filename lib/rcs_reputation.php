<?php

class rcs_reputation
{
    /** @var array<int, rcs_provider_interface> */
    private array $providers;
    private rcs_cache $cache;
    private rcube_config $config;

    /**
     * @param array<int, rcs_provider_interface> $providers
     */
    public function __construct(array $providers, rcs_cache $cache, rcube_config $config)
    {
        $this->providers = $providers;
        $this->cache = $cache;
        $this->config = $config;
    }

    /**
     * @param array<string, mixed> $normalized
     * @return array<string, mixed>
     */
    public function evaluate(array $normalized): array
    {
        $cacheKey = $this->cache->build_key('reputation', [
            'origin_ip' => (string) ($normalized['origin_ip'] ?? ''),
            'from_domain' => (string) ($normalized['from']['domain'] ?? ''),
            'version' => (string) $this->config->get('rcs_analysis_version', '2'),
        ]);

        $cached = $this->cache->get('reputation', $cacheKey);
        if ($cached !== null) {
            return $cached;
        }

        $aggregate = [
            'rdns' => '',
            'country' => '',
            'trusted_sender' => false,
            'trusted_network' => false,
            'blacklist_hit' => false,
            'provider_data' => [],
        ];

        foreach ($this->providers as $provider) {
            if (!$provider->is_enabled()) {
                continue;
            }

            try {
                $data = $provider->enrich($normalized);
            } catch (Throwable $e) {
                rcs_helpers::debug_log($this->config, 'provider_failure', [
                    'provider' => $provider->get_name(),
                    'message' => $e->getMessage(),
                ]);
                $data = [
                    'provider' => $provider->get_name(),
                    'error' => $e->getMessage(),
                ];
            }

            $aggregate['provider_data'][$provider->get_name()] = $data;

            if ($aggregate['rdns'] === '' && !empty($data['rdns'])) {
                $aggregate['rdns'] = (string) $data['rdns'];
            }
            if ($aggregate['country'] === '' && !empty($data['country'])) {
                $aggregate['country'] = (string) $data['country'];
            }
            if (!empty($data['trusted_sender'])) {
                $aggregate['trusted_sender'] = true;
            }
            if (!empty($data['trusted_network'])) {
                $aggregate['trusted_network'] = true;
            }
            if (!empty($data['blacklist_hit'])) {
                $aggregate['blacklist_hit'] = true;
            }
            if (!empty($data['hits']) && is_array($data['hits'])) {
                $aggregate['blacklist_hit'] = true;
            }
            if (!empty($data['details']['dns']['ip_is_private_or_reserved'])) {
                $aggregate['ip_is_private_or_reserved'] = true;
            }
        }

        $this->cache->set(
            'reputation',
            $cacheKey,
            $aggregate,
            (int) $this->config->get('rcs_cache_ttl_reputation', 43200)
        );

        return $aggregate;
    }
}
