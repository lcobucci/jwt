<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

/**
 * This class represents a token signature
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Signature
{
    /**
     * @var string
     */
    private $hash;

    /**
     * @var string
     */
    private $encoded;

    public static function fromEmptyData(): self
    {
        return new self('', '');
    }

    public function __construct(string $hash, string $encoded)
    {
        $this->hash = $hash;
        $this->encoded = $encoded;
    }

    public function hash(): string
    {
        return $this->hash;
    }

    /**
     * Returns the encoded version of the signature
     */
    public function __toString(): string
    {
        return $this->encoded;
    }
}
