<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use BadMethodCallException;
use Generator;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Claim\Validatable;
use OutOfBoundsException;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Token
{
    /**
     * The token headers
     *
     * @var array
     */
    private $headers;

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
     * @param array $headers
     * @param array $claims
     * @param Signature $signature
     */
    public function __construct(
        array $headers = ['alg' => 'none'],
        array $claims = [],
        Signature $signature = null
    ) {
        $this->headers = $headers;
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
     * Returns the token headers
     *
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
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
     * Returns the value of a token claim
     *
     * @param string $name
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getClaim($name)
    {
        if (!isset($this->claims[$name])) {
            throw new OutOfBoundsException('Requested claim is not configured');
        }

        return $this->claims[$name]->getValue();
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer $signer
     * @param string $key
     *
     * @return boolean
     *
     * @throws BadMethodCallException When token is not signed
     */
    public function verify(Signer $signer, $key)
    {
        if ($this->signature === null) {
            throw new BadMethodCallException('This token is not signed');
        }

        if ($this->headers['alg'] !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
    }

    /**
     * Validates if the token is valid
     *
     * @param ValidationData $data
     *
     * @return boolean
     */
    public function validate(ValidationData $data)
    {
        foreach ($this->getValidatableClaims() as $claim) {
            if (!$claim->validate($data)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Yields the validatable claims
     *
     * @return Generator
     */
    private function getValidatableClaims()
    {
        foreach ($this->claims as $claim) {
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
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
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->headers)),
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
