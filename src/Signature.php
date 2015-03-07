<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

/**
 * This class represents a token signature
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Signature
{
    /**
     * The signer that created this signature
     *
     * @var Signer
     */
    protected $signer;

    /**
     * The resultant hash
     *
     * @var string
     */
    protected $hash;

    /**
     * Initializes the object
     *
     * @param Signer $signer
     * @param string $hash
     */
    public function __construct(Signer $signer, $hash)
    {
        $this->signer = $signer;
        $this->hash = $hash;
    }

    /**
     * Verifies if the current hash matches with with the result of the creation of
     * a new signature with given data
     *
     * @param string $payload
     * @param string $key
     *
     * @return boolean
     */
    public function verify($payload, $key)
    {
        return $this->signer->verify($this->hash, $payload, $key);
    }

    /**
     * Returns the current hash as a string representation of the signature
     *
     * @return string
     */
    public function __toString()
    {
        return $this->hash;
    }
}
