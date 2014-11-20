<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;

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
                'HS512' => [$this, 'createHmacSha512']
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
     * @return Sha256
     */
    private function createHmacSha256()
    {
        return new Sha256();
    }

    /**
     * @return Sha384
     */
    private function createHmacSha384()
    {
        return new Sha384();
    }

    /**
     * @return Sha512
     */
    private function createHmacSha512()
    {
        return new Sha512();
    }
}
