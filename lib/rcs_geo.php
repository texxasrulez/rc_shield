<?php

class rcs_geo
{
    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function locate(array $context): array
    {
        $ip = (string) ($context['origin_ip'] ?? '');
        $country = '';

        if ($ip !== '' && rcs_helpers::ip_is_private_or_reserved($ip)) {
            $country = 'Private/Reserved';
        }

        return [
            'country' => $country,
            'source' => $country !== '' ? 'local' : 'unavailable',
        ];
    }
}
