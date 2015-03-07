<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as EcdsaSha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as EcdsaSha384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as EcdsaSha512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HmacSha256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HmacSha384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HmacSha512;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RsaSha256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RsaSha384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RsaSha512;

/**
 * Factory that returns instance of signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Factory
{
    /**
     * The list of signers callbacks
     *
     * @var array
     */
    private $callbacks;

    /**
     * Initializes the factory, registering the default callbacks
     *
     * @param array $callbacks
     */
    public function __construct(array $callbacks = [])
    {
        $this->callbacks = array_merge(
            [
                'HS256' => [$this, 'createHmacSha256'],
                'HS384' => [$this, 'createHmacSha384'],
                'HS512' => [$this, 'createHmacSha512'],
                'ES256' => [$this, 'createEcdsaSha256'],
                'ES384' => [$this, 'createEcdsaSha384'],
                'ES512' => [$this, 'createEcdsaSha512'],
                'RS256' => [$this, 'createRsaSha256'],
                'RS384' => [$this, 'createRsaSha384'],
                'RS512' => [$this, 'createRsaSha512']
            ],
            $callbacks
        );
    }

    /**
     * Retrieves a signer instance
     *
     * @param string $id
     *
     * @return Signer
     *
     * @throws InvalidArgumentException When signer is not implemented or invalid
     */
    public function create($id)
    {
        if (isset($this->callbacks[$id])) {
            return call_user_func($this->callbacks[$id]);
        }

        throw new InvalidArgumentException('Invalid signer');
    }

    /**
     * @return HmacSha256
     */
    private function createHmacSha256()
    {
        return new HmacSha256();
    }

    /**
     * @return HmacSha384
     */
    private function createHmacSha384()
    {
        return new HmacSha384();
    }

    /**
     * @return HmacSha512
     */
    private function createHmacSha512()
    {
        return new HmacSha512();
    }

    /**
     * @return RsaSha256
     */
    private function createRsaSha256()
    {
        return new RsaSha256();
    }

    /**
     * @return RsaSha384
     */
    private function createRsaSha384()
    {
        return new RsaSha384();
    }

    /**
     * @return RsaSha512
     */
    private function createRsaSha512()
    {
        return new RsaSha512();
    }

    /**
     * @return EcdsaSha256
     */
    private function createEcdsaSha256()
    {
        return new EcdsaSha256();
    }

    /**
     * @return EcdsaSha384
     */
    private function createEcdsaSha384()
    {
        return new EcdsaSha384();
    }

    /**
     * @return EcdsaSha512
     */
    private function createEcdsaSha512()
    {
        return new EcdsaSha512();
    }
}
