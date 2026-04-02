<?php

class rcs_header_parser
{
    /**
     * @param array<string, string|array<int, string>> $headers
     * @param string $rawHeaders
     * @return array<string, mixed>
     */
    public function parse(array $headers, string $rawHeaders = ''): array
    {
        $normalized = [
            'spf' => ['result' => 'none', 'domain' => '', 'raw' => ''],
            'dkim' => ['result' => 'none', 'domain' => '', 'raw' => ''],
            'dmarc' => ['result' => 'none', 'domain' => '', 'raw' => ''],
            'from' => rcs_helpers::parse_address(rcs_helpers::raw_header_value($headers, 'from')),
            'reply_to' => rcs_helpers::parse_address(rcs_helpers::raw_header_value($headers, 'reply-to')),
            'return_path' => rcs_helpers::parse_address(rcs_helpers::raw_header_value($headers, 'return-path')),
            'message_id' => rcs_helpers::normalize_whitespace(rcs_helpers::raw_header_value($headers, 'message-id')),
            'received_chain' => [],
            'origin_ip' => '',
            'rdns' => '',
            'helo' => '',
            'warnings' => [],
            'x_headers' => [],
        ];

        $authHeaders = array_merge(
            rcs_helpers::raw_header_values($headers, 'authentication-results'),
            rcs_helpers::raw_header_values($headers, 'x-dkim-authentication-results')
        );
        $normalized = $this->parse_authentication_results($authHeaders, $normalized);

        $dkimHeaders = rcs_helpers::raw_header_values($headers, 'dkim-signature');
        if (!empty($dkimHeaders) && $normalized['dkim']['domain'] === '') {
            $normalized['dkim']['domain'] = $this->extract_dkim_domain($dkimHeaders[0]);
        }

        $receivedHeaders = rcs_helpers::raw_header_values($headers, 'received');
        $normalized['received_chain'] = $this->parse_received_chain($receivedHeaders);
        $normalized['origin_ip'] = $this->select_origin_ip($normalized['received_chain']);
        $normalized['rdns'] = $this->select_origin_rdns($normalized['received_chain']);
        $normalized['helo'] = $this->select_helo($normalized['received_chain']);

        foreach ($headers as $name => $value) {
            if (str_starts_with($name, 'x-')) {
                $normalized['x_headers'][$name] = $value;
            }
        }

        if ($normalized['message_id'] === '') {
            $normalized['warnings'][] = 'missing_message_id';
        }

        if ($normalized['from']['email'] === '') {
            $normalized['warnings'][] = 'missing_from';
        }

        if ($rawHeaders !== '') {
            $normalized['raw_header_count'] = substr_count($rawHeaders, "\n");
        }

        return $normalized;
    }

    /**
     * @param array<int, string> $authHeaders
     * @param array<string, mixed> $normalized
     * @return array<string, mixed>
     */
    private function parse_authentication_results(array $authHeaders, array $normalized): array
    {
        foreach ($authHeaders as $header) {
            $flat = rcs_helpers::normalize_whitespace($header);

            foreach (['spf', 'dkim', 'dmarc'] as $method) {
                if (preg_match('/\b' . preg_quote($method, '/') . '\s*=\s*([a-z_]+)/i', $flat, $matches)) {
                    $normalized[$method]['result'] = rcs_helpers::normalize_result($matches[1]);
                    $normalized[$method]['raw'] = $flat;
                }

                if ($normalized[$method]['domain'] === '' && preg_match('/\b' . preg_quote($method, '/') . '\s*=\s*[a-z_]+[^;]*\b(?:header\.from|smtp\.mailfrom|header\.d|d)\s*=\s*([^;\s]+)/i', $flat, $matches)) {
                    $normalized[$method]['domain'] = rcs_helpers::normalize_domain($matches[1]);
                }
            }
        }

        return $normalized;
    }

    private function extract_dkim_domain(string $header): string
    {
        if (preg_match('/\bd=([^;\s]+)/i', $header, $matches)) {
            return rcs_helpers::normalize_domain($matches[1]);
        }

        return '';
    }

    /**
     * @param array<int, string> $receivedHeaders
     * @return array<int, array<string, string>>
     */
    private function parse_received_chain(array $receivedHeaders): array
    {
        $chain = [];

        foreach ($receivedHeaders as $header) {
            $flat = rcs_helpers::normalize_whitespace($header);
            $hop = [
                'raw' => $flat,
                'from' => '',
                'by' => '',
                'helo' => '',
                'ip' => '',
                'rdns' => '',
            ];

            if (preg_match('/\bfrom\s+([^\s(]+)(?:\s+\(([^)]+)\))?/i', $flat, $matches)) {
                $hop['from'] = strtolower(trim($matches[1]));
                if (!empty($matches[2])) {
                    $hop['rdns'] = strtolower(trim($matches[2]));
                }
            }

            if (preg_match('/\bby\s+([^\s;]+)/i', $flat, $matches)) {
                $hop['by'] = strtolower(trim($matches[1]));
            }

            if (preg_match('/\bhelo=([^\s;]+)/i', $flat, $matches)) {
                $hop['helo'] = strtolower(trim($matches[1]));
            }

            if (preg_match('/\[((?:\d{1,3}\.){3}\d{1,3})\]/', $flat, $matches)) {
                $hop['ip'] = $matches[1];
            } elseif (preg_match('/\b((?:\d{1,3}\.){3}\d{1,3})\b/', $flat, $matches)) {
                $hop['ip'] = $matches[1];
            }

            $chain[] = $hop;
        }

        return $chain;
    }

    /**
     * Security: prefer the earliest public IP outside local/private space to avoid trusting internal hops.
     *
     * @param array<int, array<string, string>> $chain
     */
    private function select_origin_ip(array $chain): string
    {
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $candidate = (string) ($chain[$i]['ip'] ?? '');
            if (rcs_helpers::ip_is_public($candidate)) {
                return $candidate;
            }
        }

        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $candidate = (string) ($chain[$i]['ip'] ?? '');
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return '';
    }

    /**
     * @param array<int, array<string, string>> $chain
     */
    private function select_origin_rdns(array $chain): string
    {
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            $candidate = (string) ($chain[$i]['from'] ?? '');
            if ($candidate !== '' && !filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return '';
    }

    /**
     * @param array<int, array<string, string>> $chain
     */
    private function select_helo(array $chain): string
    {
        foreach ($chain as $hop) {
            if (!empty($hop['helo'])) {
                return (string) $hop['helo'];
            }
        }

        return '';
    }
}
