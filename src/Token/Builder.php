<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token as TokenInterface;

/**
 * This class makes easier the token creation process
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Builder implements BuilderInterface
{
    /**
     * The token header
     *
     * @var array
     */
    private $headers = ['typ'=> 'JWT', 'alg' => 'none'];

    /**
     * The token claim set
     *
     * @var array
     */
    private $claims = [];

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
    }

    /**
     * {@inheritdoc}
     */
    public function permittedFor(string $audience, bool $addHeader = false): BuilderInterface
    {
        $audiences = $this->claims[RegisteredClaims::AUDIENCE] ?? [];

        if (!in_array($audience, $audiences)) {
            $audiences[] = $audience;
        }

        return $this->setRegisteredClaim(RegisteredClaims::AUDIENCE, $audiences, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function expiresAt(int $expiration, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::EXPIRATION_TIME, $expiration, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function identifiedBy(string $id, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::ID, $id, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function issuedAt(int $issuedAt, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::ISSUED_AT, (int) $issuedAt, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function issuedBy(string $issuer, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::ISSUER, $issuer, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function canOnlyBeUsedAfter(int $notBefore, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::NOT_BEFORE, $notBefore, $addHeader);
    }

    /**
     * {@inheritdoc}
     */
    public function relatedTo(string $subject, bool $addHeader = false): BuilderInterface
    {
        return $this->setRegisteredClaim(RegisteredClaims::SUBJECT, $subject, $addHeader);
    }

    /**
     * Configures a registered claim
     */
    private function setRegisteredClaim(string $name, $value, bool $addHeader): BuilderInterface
    {
        $this->withClaim($name, $value);

        if ($addHeader) {
            $this->headers[$name] = $this->claims[$name];
        }

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function withHeader(string $name, $value): BuilderInterface
    {
        $this->headers[$name] = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function withClaim(string $name, $value): BuilderInterface
    {
        $this->claims[$name] = $value;

        return $this;
    }

    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getToken(Signer $signer, Key $key): Plain
    {
        $headers = $this->headers;
        $headers['alg'] = $signer->getAlgorithmId();

        $encodedHeaders = $this->encode($headers);
        $encodedClaims = $this->encode($this->claims);

        $signature = $signer->sign($encodedHeaders . '.' . $encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Plain(
            new DataSet($headers, $encodedHeaders),
            new DataSet($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature)
        );
    }
}
