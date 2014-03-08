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
 * This class makes easier the token creation process
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Builder
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
     * Initializes a new builder
     */
    public function __construct(Encoder $encoder = null)
    {
        $this->encoder = $encoder ?: new Encoder();
        $this->header = ['typ'=> 'JWT', 'alg' => 'none'];
        $this->claims = [];
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setAudience($audience, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('aud', (string) $audience, $replicateAsHeader);
    }

    /**
     * Configures the expiration time
     *
     * @param int $expiration
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setExpiration($expiration, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('exp', (int) $expiration, $replicateAsHeader);
    }

    /**
     * Configures the token id
     *
     * @param string $id
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setId($id, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('jti', (string) $id, $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param int $issuedAt
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssueAt($issuedAt, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('iat', (int) $issuedAt, $replicateAsHeader);
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssuer($issuer, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('iss', (string) $issuer, $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param int $notBefore
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setNotBefore($notBefore, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('nbf', (int) $notBefore, $replicateAsHeader);
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setSubject($subject, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('sub', (string) $subject, $replicateAsHeader);
    }

    /**
     * Configures a registed claim
     *
     * @param string $name
     * @param mixed $value
     * @param boolean $replicate
     *
     * @return Builder
     */
    protected function setRegisteredClaim($name, $value, $replicate)
    {
        $this->set($name, $value);

        if ($replicate) {
            $this->header[$name] = $value;
        }

        return $this;
    }

    /**
     * Configures a claim item
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     *
     * @throws BadMethodCallException When data has been already signed
     */
    public function set($name, $value)
    {
        if ($this->signature) {
            throw new BadMethodCallException('You must unsign before make changes');
        }

        $this->claims[(string) $name] = $value;

        return $this;
    }

    /**
     * Signs the data
     *
     * @param Signer $signer
     * @param string $key
     *
     * @return Builder
     */
    public function sign(Signer $signer, $key)
    {
        $signer->modifyHeader($this->header);

        $this->signature = $signer->sign(
            $this->getToken()->getPayload(),
            $key
        );

        return $this;
    }

    /**
     * Removes the signature from the builder
     *
     * @return Builder
     */
    public function unsign()
    {
        $this->signature = null;

        return $this;
    }

    /**
     * Returns the resultant token
     *
     * @return Token
     */
    public function getToken()
    {
        $token = new Token($this->header, $this->claims, $this->signature);
        $token->setEncoder($this->encoder);

        return $token;
    }
}
