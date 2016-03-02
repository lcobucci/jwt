<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer;

/**
 * Base class for signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
abstract class BaseSigner implements Signer
{
    /**
     * {@inheritdoc}
     */
    public function modifyHeader(array &$headers)
    {
        $headers['alg'] = $this->getAlgorithmId();
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, $key): Signature
    {
        return new Signature($this->createHash($payload, $this->getKey($key)));
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, $key): bool
    {
        return $this->doVerify($expected, $payload, $this->getKey($key));
    }

    /**
     * @param Key|string $key
     *
     * @return Key
     */
    private function getKey($key): Key
    {
        if (is_string($key)) {
            $key = new Key($key);
        }

        return $key;
    }

    /**
     * Creates a hash with the given data
     *
     * @param string $payload
     * @param Key $key
     *
     * @return string
     */
    abstract public function createHash(string $payload, Key $key): string;

    /**
     * Creates a hash with the given data
     *
     * @param string $expected
     * @param string $payload
     * @param Key $key
     *
     * @return bool
     */
    abstract public function doVerify(string $expected, string $payload, Key $key): bool;
}
