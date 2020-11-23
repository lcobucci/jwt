<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;

/**
 * This class represents a token signature
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Signature
{
    /**
     * The resultant hash
     *
     * @var string
     */
    protected $hash;

    /** @var string */
    private $encoded;

    /**
     * Initializes the object
     *
     * @param string $hash
     * @param string $encoded
     */
    public function __construct($hash, $encoded = '')
    {
        $this->hash    = $hash;
        $this->encoded = $encoded;
    }

    /** @return self */
    public static function fromEmptyData()
    {
        return new self('', '');
    }

    /**
     * Verifies if the current hash matches with with the result of the creation of
     * a new signature with given data
     *
     * @param Signer $signer
     * @param string $payload
     * @param Key|string $key
     *
     * @return boolean
     */
    public function verify(Signer $signer, $payload, $key)
    {
        return $signer->verify($this->hash, $payload, $key);
    }

    /**
     * Returns the current hash as a string representation of the signature
     *
     * @deprecated This method has been removed from the public API in v4
     * @see Signature::hash()
     *
     * @return string
     */
    public function __toString()
    {
        return $this->hash;
    }

    /** @return string */
    public function hash()
    {
        return $this->hash;
    }

    /** @return string */
    public function toString()
    {
        return $this->encoded;
    }
}
