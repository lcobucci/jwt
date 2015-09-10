<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;

/**
 * Base class for RSASSA-PKCS1 signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
abstract class Rsa extends BaseSigner
{
    /**
     * {@inheritdoc}
     */
    public function createHash($payload, Key $key)
    {
        $key = openssl_get_privatekey($key->getContent(), $key->getPassphrase());
        $this->validateKey($key);

        $signature = '';
        openssl_sign($payload, $signature, $key, $this->getAlgorithm());

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function doVerify($expected, $payload, Key $key)
    {
        $key = openssl_get_publickey($key->getContent());
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

        if (!isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidArgumentException('This key is not compatible with RSA signatures');
        }
    }

    /**
     * Returns the algorithm name
     *
     * @return string
     */
    abstract public function getAlgorithm();
}
