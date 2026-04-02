<?php

interface rcs_provider_interface
{
    public function get_name(): string;

    public function is_enabled(): bool;

    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public function enrich(array $context): array;
}
