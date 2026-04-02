<?php

class rcs_storage
{
    private rcmail $rcmail;

    public function __construct(rcmail $rcmail)
    {
        $this->rcmail = $rcmail;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function load_message_context(int $uid, string $mailbox): ?array
    {
        $mailbox = rcs_helpers::sanitize_mailbox($mailbox);
        if ($uid <= 0 || $mailbox === '') {
            return null;
        }

        $storage = $this->rcmail->storage;
        if (method_exists($storage, 'set_folder')) {
            try {
                $storage->set_folder($mailbox);
            } catch (Throwable $e) {
                return null;
            }
        }

        $message = new rcube_message($uid, $mailbox);
        if (!$message || empty($message->uid)) {
            return null;
        }

        $rawMessage = '';
        if (method_exists($storage, 'get_raw_message')) {
            try {
                $rawMessage = (string) $storage->get_raw_message($uid, $mailbox);
            } catch (Throwable $e) {
                $rawMessage = '';
            }
        }

        $rawHeaders = '';
        if (method_exists($storage, 'get_raw_headers')) {
            try {
                $rawHeaders = (string) $storage->get_raw_headers($uid, $mailbox);
            } catch (Throwable $e) {
                $rawHeaders = '';
            }
        }

        if ($rawHeaders === '' && $rawMessage !== '') {
            $parts = preg_split("/\r?\n\r?\n/", $rawMessage, 2);
            $rawHeaders = (string) ($parts[0] ?? '');
        }

        $headers = $this->headers_to_array($message->headers ?? null, $rawHeaders);
        $messageId = rcs_helpers::raw_header_value($headers, 'message-id');
        $identityHash = sha1($mailbox . '|' . $uid . '|' . $messageId . '|' . (string) ($message->headers->date ?? ''));

        return [
            'uid' => $uid,
            'mailbox' => $mailbox,
            'message' => $message,
            'headers' => $headers,
            'raw_headers' => $rawHeaders,
            'identity_hash' => $identityHash,
        ];
    }

    /**
     * @param mixed $headerObject
     * @return array<string, string|array<int, string>>
     */
    private function headers_to_array($headerObject, string $rawHeaders): array
    {
        $headers = [];

        if (is_object($headerObject)) {
            foreach (get_object_vars($headerObject) as $name => $value) {
                $normalized = $this->normalize_header_value($value);
                if ($normalized === null) {
                    continue;
                }

                $headers[rcs_helpers::normalize_header_name((string) $name)] = $normalized;
            }
        }

        if ($rawHeaders !== '') {
            $parsed = $this->parse_raw_header_block($rawHeaders);
            foreach ($parsed as $name => $value) {
                $headers[$name] = $value;
            }
        }

        return $headers;
    }

    /**
     * @return array<string, string|array<int, string>>
     */
    private function parse_raw_header_block(string $rawHeaders): array
    {
        $headers = [];
        $currentName = '';
        $currentValue = '';

        foreach (preg_split('/\r?\n/', $rawHeaders) as $line) {
            if ($line === '') {
                continue;
            }

            if (preg_match('/^[ \t]/', $line) && $currentName !== '') {
                $currentValue .= ' ' . trim($line);
                continue;
            }

            if ($currentName !== '') {
                $this->append_header_value($headers, $currentName, $currentValue);
            }

            [$name, $value] = array_pad(explode(':', $line, 2), 2, '');
            $currentName = rcs_helpers::normalize_header_name($name);
            $currentValue = trim($value);
        }

        if ($currentName !== '') {
            $this->append_header_value($headers, $currentName, $currentValue);
        }

        return $headers;
    }

    /**
     * @param array<string, string|array<int, string>> $headers
     */
    private function append_header_value(array &$headers, string $name, string $value): void
    {
        if (isset($headers[$name])) {
            $existing = $headers[$name];
            if (!is_array($existing)) {
                $existing = [$existing];
            }
            $existing[] = $value;
            $headers[$name] = $existing;
            return;
        }

        $headers[$name] = $value;
    }

    /**
     * @param mixed $value
     * @return string|array<int, string>|null
     */
    private function normalize_header_value($value)
    {
        if ($value === null) {
            return null;
        }

        if (is_scalar($value)) {
            return (string) $value;
        }

        if (is_array($value)) {
            $result = [];

            foreach ($value as $item) {
                if ($item === null) {
                    continue;
                }

                if (is_scalar($item)) {
                    $result[] = (string) $item;
                }
            }

            return $result === [] ? null : $result;
        }

        return null;
    }
}
