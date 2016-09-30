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
     * Initializes a new builder
     */
    public function __construct(Parsing\Encoder $encoder)
    {
        $this->encoder = $encoder;
        $this->headers = ['typ'=> 'JWT', 'alg' => 'none'];
        $this->claims = [];
    }

    /**
     * Configures the audience
     *
     * @param string|array $audience
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedBy(string $audience, bool $addHeader = false): Builder
    {
        $audiences = $this->claims['aud'] ?? [];
        $audiences[] = $audience;

        return $this->setRegisteredClaim(
            'aud',
            array_values(array_map('strval', $audiences)),
            $addHeader
        );
    }

    /**
     * Configures the expiration time
     *
     * @param int $expiration
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function expiresAt(int $expiration, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('exp', $expiration, $addHeader);
    }

    /**
     * Configures the token id
     *
     * @param string $id
     * @param boolean $addHeader
     *
     * @return Builder
     */
    public function withId(string $id, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('jti', $id, $addHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param int $issuedAt
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function issuedAt(int $issuedAt, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('iat', (int) $issuedAt, $addHeader);
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function issuedBy(string $issuer, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('iss', $issuer, $addHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param int $notBefore
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedAfter(int $notBefore, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('nbf', $notBefore, $addHeader);
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     * @param bool $addHeader
     *
     * @return Builder
     */
    public function relatedTo(string $subject, bool $addHeader = false): Builder
    {
        return $this->setRegisteredClaim('sub', $subject, $addHeader);
    }

    /**
     * Configures a registed claim
     *
     * @param string $name
     * @param mixed $value
     * @param bool $addHeader
     *
     * @return Builder
     */
    protected function setRegisteredClaim(string $name, $value, bool $addHeader): Builder
    {
        $this->with($name, $value);

        if ($addHeader) {
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
    public function withHeader(string $name, $value): Builder
    {
        if ($this->signature) {
            throw new BadMethodCallException('You must unsign before make changes');
        }

        $this->headers[$name] = $value;

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
    public function with(string $name, $value): Builder
    {
        if ($this->signature) {
            throw new BadMethodCallException('You must unsign before making changes');
        }

        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * Signs the data
     *
     * @param Signer $signer
     * @param Key $key
     *
     * @return Builder
     */
    public function sign(Signer $signer, Key $key): Builder
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
