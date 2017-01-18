<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key;

/**
 * Basic interface for token signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
interface Signer
{
    /**
     * Returns the algorithm id
     *
     * @return string
     */
    public function getAlgorithmId(): string;

    /**
     * Creates a hash for the given payload
     *
     * @param string $payload
     * @param Key $key
     *
     * @return string
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function sign(string $payload, Key $key): string;

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param string $expected
     * @param string $payload
     * @param Key $key
     *
     * @return bool
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function verify(string $expected, string $payload, Key $key): bool;
}
