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
     * Apply changes on headers according with algorithm
     *
     * @param array $headers
     */
    public function modifyHeader(array &$headers);

    /**
     * Returns a signature for given data
     *
     * @param string $payload
     * @param Key|string $key
     *
     * @return Signature
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function sign(string $payload, $key): Signature;

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @param string $expected
     * @param string $payload
     * @param Key|string $key
     *
     * @return bool
     *
     * @throws InvalidArgumentException When given key is invalid
     */
    public function verify(string $expected, string $payload, $key): bool;
}
