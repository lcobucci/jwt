<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;

/**
 * @author Luís Cobucci <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class None implements Signer
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, Key $key): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $expected === '';
    }
}
