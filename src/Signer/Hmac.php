<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;

/**
 * Base class for hmac signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
abstract class Hmac implements Signer
{
    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
    {
        return \hash_hmac($this->getAlgorithm(), $payload, $key->getContent(), true);
    }

    /**
     * {@inheritdoc}
     */
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return \hash_equals($expected, $this->sign($payload, $key));
    }

    /**
     * Returns the algorithm name
     *
     * @return string
     */
    abstract public function getAlgorithm(): string;
}
