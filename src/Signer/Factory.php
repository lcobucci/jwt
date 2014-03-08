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
     * Retrives a signer instance
     *
     * @param string $id
     *
     * @return Signer
     *
     * @throws InvalidArgumentException When signer is not implemented or invalid
     */
    public function create($id)
    {
        if ($id === 'HS256') {
            return new Sha256();
        }

        if ($id === 'HS384') {
            return new Sha384();
        }

        if ($id === 'HS512') {
            return new Sha512();
        }

        throw new InvalidArgumentException('Invalid signer');
    }
}
