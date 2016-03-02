<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use BadMethodCallException;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Signer\Key;

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
     * @var Parsing\Encoder
     */
    private $encoder;

    /**
     * The factory of claims
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    /**
     * Initializes a new builder
     *
     * @param Parsing\Encoder $encoder
     * @param ClaimFactory $claimFactory
     */
    public function __construct(
        Parsing\Encoder $encoder = null,
        ClaimFactory $claimFactory = null
    ) {
        $this->encoder = $encoder ?: new Parsing\Parser();
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
        $this->headers = ['typ'=> 'JWT', 'alg' => 'none'];
        $this->claims = [];
    }

    /**
     * Configures the audience
     *
     * @param string|array $audience
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setAudience($audience, bool $replicateAsHeader = false): Builder
    {
        if (is_array($audience)) {
            foreach($audience as $key => $member) {
                $audience[$key] = (string) $member;
            }
            return $this->setRegisteredClaim('aud', $audience, $replicateAsHeader);
        } else {
            return $this->setRegisteredClaim('aud', [(string) $audience], $replicateAsHeader);
        }
    }

    /**
     * Configures the expiration time
     *
     * @param int $expiration
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setExpiration(int $expiration, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('exp', $expiration, $replicateAsHeader);
    }

    /**
     * Configures the token id
     *
     * @param string $id
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setId(string $id, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('jti', $id, $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param int $issuedAt
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssuedAt(int $issuedAt, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('iat', (int) $issuedAt, $replicateAsHeader);
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssuer(string $issuer, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('iss', $issuer, $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param int $notBefore
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setNotBefore(int $notBefore, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('nbf', $notBefore, $replicateAsHeader);
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function setSubject(string $subject, bool $replicateAsHeader = false): Builder
    {
        return $this->setRegisteredClaim('sub', $subject, $replicateAsHeader);
    }

    /**
     * Configures a registed claim
     *
     * @param string $name
     * @param mixed $value
     * @param bool $replicate
     *
     * @return Builder
     */
    protected function setRegisteredClaim(string $name, $value, bool $replicate): Builder
    {
        $this->set($name, $value);

        if ($replicate) {
            $this->headers[$name] = $this->claims[$name];
        }

        return $this;
    }

    /**
     * Configures a header item
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     *
     * @throws BadMethodCallException When data has been already signed
     */
    public function setHeader(string $name, $value): Builder
    {
        if ($this->signature) {
            throw new BadMethodCallException('You must unsign before make changes');
        }

        $this->headers[$name] = $this->claimFactory->create($name, $value);
        
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
    public function set(string $name, $value): Builder
    {
        if ($this->signature) {
            throw new BadMethodCallException('You must unsign before make changes');
        }

        $this->claims[$name] = $this->claimFactory->create($name, $value);

        return $this;
    }

    /**
     * Signs the data
     *
     * @param Signer $signer
     * @param Key|string $key
     *
     * @return Builder
     */
    public function sign(Signer $signer, $key): Builder
    {
        $signer->modifyHeader($this->headers);

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
    public function unsign(): Builder
    {
        $this->signature = null;

        return $this;
    }

    /**
     * Returns the resultant token
     *
     * @return Token
     */
    public function getToken(): Token
    {
        $payload = [
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->headers)),
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->claims))
        ];

        if ($this->signature !== null) {
            $payload[] = $this->encoder->base64UrlEncode((string) $this->signature);
        }

        return new Token($this->headers, $this->claims, $this->signature, $payload);
    }
}
