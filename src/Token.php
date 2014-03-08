<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use BadMethodCallException;
use Lcobucci\JWT\Parsing\Encoder;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Token
{
    /**
     * The token header
     *
     * @var array
     */
    private $header;

    /**
     * The token claim set
     *
     * @var array
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature
     */
    private $signature;

    /**
     * The data encoder
     *
     * @var Encoder
     */
    private $encoder;

    /**
     * Initializes the object
     *
     * @param array $header
     * @param array $claims
     * @param Signature $signature
     */
    public function __construct(array $header = ['alg' => 'none'], array $claims = [], Signature $signature = null)
    {
        $this->header = $header;
        $this->claims = $claims;
        $this->signature = $signature;
    }

    /**
     * Configures the data encoder
     *
     * @param Encoder $encoder
     */
    public function setEncoder(Encoder $encoder)
    {
        $this->encoder = $encoder;
    }

    /**
     * Returns the token header
     *
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Returns the token claim set
     *
     * @return array
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Returns the token signature
     *
     * @return Signature
     */
    public function getSignature()
    {
        return $this->signature;
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param string $key
     *
     * @return boolean
     *
     * @throws BadMethodCallException When token is not signed
     */
    public function verify($key)
    {
        if ($this->signature === null) {
            throw new BadMethodCallException('This token is not signed');
        }

        return $this->signature->verify($this->getPayload(), $key);
    }

    /**
     * Returns the token payload
     *
     * @return string
     *
     * @throws BadMethodCallException When $this->encoder is not configured
     */
    public function getPayload()
    {
        if ($this->encoder === null) {
            throw new BadMethodCallException('Encoder must be configured');
        }

        return sprintf(
            '%s.%s',
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->header)),
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->claims))
        );
    }

    /**
     * Returns an encoded representation of the token
     *
     * @return string
     */
    public function __toString()
    {
        try {
            $data = $this->getPayload() . '.';

            if ($this->signature) {
                $data .= $this->encoder->base64UrlEncode($this->signature);
            }

            return $data;
        } catch (BadMethodCallException $e) {
            return '';
        }
    }
}
