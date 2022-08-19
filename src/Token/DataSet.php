<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use function array_key_exists;

final class DataSet
{
    /** @param array<string, mixed> $data */
    public function __construct(private readonly array $data, private readonly string $encoded)
    {
    }

    public function get(string $name, mixed $default = null): mixed
    {
        return $this->data[$name] ?? $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    /** @return array<string, mixed> */
    public function all(): array
    {
        return $this->data;
    }

    public function toString(): string
    {
        return $this->encoded;
    }
}
