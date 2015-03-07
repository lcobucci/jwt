<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;

/**
 * A utilitarian class that encapsulates the retrieval of public and private keys
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class Keychain
{
    /**
     * Returns a private key from file path or content
     *
     * @param string $key
     * @param string $passphrase
     *
     * @return resource
     *
     * @throws InvalidArgumentException
     */
    public function getPrivateKey($key, $passphrase = '')
    {
        if ($privateKey = openssl_pkey_get_private($key, $passphrase)) {
            return $privateKey;
        }

        throw new InvalidArgumentException(
            'You should provid a valid private key (with its passphrase when used)'
        );
    }

    /**
     * Returns a public key from file path or content
     *
     * @param string $certificate
     *
     * @return resource
     *
     * @throws InvalidArgumentException
     */
    public function getPublicKey($certificate)
    {
        if ($publicKey = openssl_pkey_get_public($certificate)) {
            return $publicKey;
        }

        throw new InvalidArgumentException('You should provid a valid certificate');
    }
}
