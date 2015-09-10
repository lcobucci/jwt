<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;

/**
 * Base class for ECDSA signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
abstract class Ecdsa extends BaseSigner
{
    /**
     * {@inheritdoc}
     */
    public function createHash($payload, Key $key)
    {
        $this->validateKey($key);

        $details = openssl_pkey_get_details($key);

        var_dump($details);

        $signature = '';
        openssl_sign($payload, $signature, $key, $this->getAlgorithm());

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function doVerify($expected, $payload, Key $key)
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

        if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_EC) {
            throw new InvalidArgumentException('The type of given key does not match with this signer');
        }
    }
}
