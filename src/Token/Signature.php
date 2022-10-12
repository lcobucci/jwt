<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

final class Signature
{
    public function __construct(private readonly string $hash, private readonly string $encoded)
    {
    }

    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * Returns the encoded version of the signature
     */
    public function toString(): string
    {
        return $this->encoded;
    }
}
