<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use function array_key_exists;

final class DataSet
{
    /**
     * @var mixed[]
     */
    private $data;

    /**
     * @var string
     */
    private $encoded;

    /**
     * @param mixed[] $data
     */
    public function __construct(array $data, string $encoded)
    {
        $this->data    = $data;
        $this->encoded = $encoded;
    }

    /**
     * @param mixed|null $default
     *
     * @return mixed|null
     */
    public function get(string $name, $default = null)
    {
        return $this->data[$name] ?? $default;
    }

    public function has(string $name): bool
    {
        return \array_key_exists($name, $this->data);
    }

    /**
     * @return mixed[]
     */
    public function all(): array
    {
        return $this->data;
    }

    public function __toString(): string
    {
        return $this->encoded;
    }
}
