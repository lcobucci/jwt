<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;

/**
 * Base class for openssl signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
abstract class OpenSSL extends BaseSigner
{
    /**
     * {@inheritdoc}
     */
    public function createHash($payload, $key)
    {
        $this->validateKey($key);

        $signature = '';
        openssl_sign($payload, $signature, $key, $this->getAlgorithm());

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function verify($expected, $payload, $key)
    {
        $this->validateKey($key);

        return openssl_verify($payload, $expected, $key, $this->getAlgorithm()) === 1;
    }

    /**
     * Returns if the key type is equals with expected type
     *
     * @param resource $key
     *
     * @return boolean
     */
    private function validateKey($key)
    {
        $details = openssl_pkey_get_details($key);

        if (!isset($details['key']) || $details['type'] !== $this->getType()) {
            throw new InvalidArgumentException('The type of given key does not match with this signer');
        }
    }

    /**
     * Returns the key type
     *
     * @return int
     */
    abstract public function getType();

    /**
     * Returns the algorithm name
     *
     * @return string
     */
    abstract public function getAlgorithm();
}
