<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
final class DataSet
{
    /**
     * @var array
     */
    private $data;

    /**
     * @var string
     */
    private $encoded;

    public function __construct(array $data, string $encoded)
    {
        $this->data    = $data;
        $this->encoded = $encoded;
    }

    public function get(string $name, $default = null)
    {
        return $this->data[$name] ?? $default;
    }

    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->data);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function __toString(): string
    {
        return $this->encoded;
    }
}
