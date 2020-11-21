<?php

namespace Lcobucci\JWT\Token;

use function array_key_exists;

final class DataSet
{
    /** @var array<string, mixed> */
    private $data;
    /** @var string */
    private $encoded;

    /**
     * @param array<string, mixed> $data
     * @param string               $encoded
     */
    public function __construct(array $data, $encoded)
    {
        $this->data    = $data;
        $this->encoded = $encoded;
    }

    /**
     * @param string     $name
     * @param mixed|null $default
     *
     * @return mixed|null
     */
    public function get($name, $default = null)
    {
        return $this->has($name) ? $this->data[$name] : $default;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function has($name)
    {
        return array_key_exists($name, $this->data);
    }

    /** @return array<string, mixed> */
    public function all()
    {
        return $this->data;
    }

    /** @return string */
    public function toString()
    {
        return $this->encoded;
    }
}
