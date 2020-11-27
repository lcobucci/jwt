<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use DateTimeImmutable;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaimGiven;
use Lcobucci\JWT\Token\RegisteredClaims;

use function array_key_exists;
use function current;
use function in_array;
use function is_array;
use function trigger_error;
use const E_USER_DEPRECATED;

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
     * @var Encoder
     */
    private $encoder;

    /**
     * The factory of claims
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    /**
     * @var Signer|null
     */
    private $signer;

    /**
     * @var Key|null
     */
    private $key;

    /**
     * Initializes a new builder
     *
     * @param Encoder $encoder
     * @param ClaimFactory $claimFactory
     */
    public function __construct(
        Encoder $encoder = null,
        ClaimFactory $claimFactory = null
    ) {
        $this->encoder = $encoder ?: new Encoder();
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
    }

    /**
     * Configures the audience
     *
     * @deprecated This method has been wrongly added and doesn't exist on v4
     * @see Builder::permittedFor()
     *
     * @param string $audience
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedBy($audience, $replicateAsHeader = false)
    {
        return $this->permittedFor($audience, $replicateAsHeader);
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     * @param bool $replicateAsHeader
     *
     * @return Builder
     */
    public function permittedFor($audience, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('aud', [(string) $audience], $replicateAsHeader);
    }

    /**
     * Configures the audience
     *
     * @deprecated This method will be removed on v4
     * @see Builder::permittedFor()
     *
     * @param string $audience
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setAudience($audience, $replicateAsHeader = false)
    {
        return $this->permittedFor($audience, $replicateAsHeader);
    }

    /**
     * Configures the expiration time
     *
     * @param int|DateTimeImmutable $expiration
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function expiresAt($expiration, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('exp', $this->convertToDate($expiration), $replicateAsHeader);
    }

    /**
     * @param int|DateTimeImmutable $value
     *
     * @return DateTimeImmutable
     */
    private function convertToDate($value)
    {
        if (! $value instanceof DateTimeImmutable) {
            trigger_error('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.', E_USER_DEPRECATED);

            return new DateTimeImmutable('@' . $value);
        }

        return $value;
    }

    /**
     * Configures the expiration time
     *
     * @deprecated This method will be removed on v4
     * @see Builder::expiresAt()
     *
     * @param int|DateTimeImmutable $expiration
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setExpiration($expiration, $replicateAsHeader = false)
    {
        return $this->expiresAt($expiration, $replicateAsHeader);
    }

    /**
     * Configures the token id
     *
     * @param string $id
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function identifiedBy($id, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('jti', (string) $id, $replicateAsHeader);
    }

    /**
     * Configures the token id
     *
     * @deprecated This method will be removed on v4
     * @see Builder::identifiedBy()
     *
     * @param string $id
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setId($id, $replicateAsHeader = false)
    {
        return $this->identifiedBy($id, $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @param int|DateTimeImmutable $issuedAt
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function issuedAt($issuedAt, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('iat', $this->convertToDate($issuedAt), $replicateAsHeader);
    }

    /**
     * Configures the time that the token was issued
     *
     * @deprecated This method will be removed on v4
     * @see Builder::issuedAt()
     *
     * @param int|DateTimeImmutable $issuedAt
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssuedAt($issuedAt, $replicateAsHeader = false)
    {
        return $this->issuedAt($issuedAt, $replicateAsHeader);
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function issuedBy($issuer, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('iss', (string) $issuer, $replicateAsHeader);
    }

    /**
     * Configures the issuer
     *
     * @deprecated This method will be removed on v4
     * @see Builder::issuedBy()
     *
     * @param string $issuer
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setIssuer($issuer, $replicateAsHeader = false)
    {
        return $this->issuedBy($issuer, $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @param int|DateTimeImmutable $notBefore
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function canOnlyBeUsedAfter($notBefore, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('nbf', $this->convertToDate($notBefore), $replicateAsHeader);
    }

    /**
     * Configures the time before which the token cannot be accepted
     *
     * @deprecated This method will be removed on v4
     * @see Builder::canOnlyBeUsedAfter()
     *
     * @param int|DateTimeImmutable $notBefore
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setNotBefore($notBefore, $replicateAsHeader = false)
    {
        return $this->canOnlyBeUsedAfter($notBefore, $replicateAsHeader);
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function relatedTo($subject, $replicateAsHeader = false)
    {
        return $this->setRegisteredClaim('sub', (string) $subject, $replicateAsHeader);
    }

    /**
     * Configures the subject
     *
     * @deprecated This method will be removed on v4
     * @see Builder::relatedTo()
     *
     * @param string $subject
     * @param boolean $replicateAsHeader
     *
     * @return Builder
     */
    public function setSubject($subject, $replicateAsHeader = false)
    {
        return $this->relatedTo($subject, $replicateAsHeader);
    }

    /**
     * Configures a registered claim
     *
     * @param string $name
     * @param mixed $value
     * @param boolean $replicate
     *
     * @return Builder
     */
    protected function setRegisteredClaim($name, $value, $replicate)
    {
        $this->configureClaim($name, $value);

        if ($replicate) {
            trigger_error('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.', E_USER_DEPRECATED);

            $this->headers[$name] = $value;
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
     */
    public function withHeader($name, $value)
    {
        $this->headers[(string) $name] = $value;

        return $this;
    }

    /**
     * Configures a header item
     *
     * @deprecated This method will be removed on v4
     * @see Builder::withHeader()
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     */
    public function setHeader($name, $value)
    {
        return $this->withHeader($name, $value);
    }

    /**
     * Configures a claim item
     *
     * @deprecated This method has been wrongly added and doesn't exist on v4
     * @see Builder::withClaim()
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     */
    public function with($name, $value)
    {
        return $this->withClaim($name, $value);
    }

    /**
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     */
    private function configureClaim($name, $value)
    {
        $this->claims[(string) $name] = $value;

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
     * @throws RegisteredClaimGiven
     */
    public function withClaim($name, $value)
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            trigger_error('The use of the method "withClaim" is deprecated for registered claims. Please use dedicated method instead.', E_USER_DEPRECATED);
        }

        return $this->forwardCallToCorrectClaimMethod($name, $value);
    }

    private function forwardCallToCorrectClaimMethod($name, $value)
    {
        switch ($name) {
            case RegisteredClaims::ID:
                return $this->identifiedBy($value);
            case RegisteredClaims::EXPIRATION_TIME:
                return $this->expiresAt($value);
            case RegisteredClaims::NOT_BEFORE:
                return $this->canOnlyBeUsedAfter($value);
            case RegisteredClaims::ISSUED_AT:
                return $this->issuedAt($value);
            case RegisteredClaims::ISSUER:
                return $this->issuedBy($value);
            case RegisteredClaims::AUDIENCE:
                return $this->permittedFor($value);
            default:
                return $this->configureClaim($name, $value);
        }
    }

    /**
     * Configures a claim item
     *
     * @deprecated This method will be removed on v4
     * @see Builder::withClaim()
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Builder
     */
    public function set($name, $value)
    {
        return $this->forwardCallToCorrectClaimMethod($name, $value);
    }

    /**
     * Signs the data
     *
     * @deprecated This method will be removed on v4
     * @see Builder::getToken()
     *
     * @param Signer $signer
     * @param Key|string $key
     *
     * @return Builder
     */
    public function sign(Signer $signer, $key)
    {
        if (! $key instanceof Key) {
            trigger_error('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.', E_USER_DEPRECATED);

            $key = new Key($key);
        }

        $this->signer = $signer;
        $this->key = $key;

        return $this;
    }

    /**
     * Removes the signature from the builder
     *
     * @deprecated This method will be removed on v4
     * @see Builder::getToken()
     *
     * @return Builder
     */
    public function unsign()
    {
        $this->signer = null;
        $this->key = null;

        return $this;
    }

    /**
     * Returns the resultant token
     *
     * @return Token
     */
    public function getToken(Signer $signer = null, Key $key = null)
    {
        if ($signer === null || $key === null) {
            trigger_error('Not specifying the signer and key to Builder#getToken() is deprecated. Please move the arguments from Builder#sign() to Builder#getToken().', E_USER_DEPRECATED);
        }

        $signer = $signer ?: $this->signer;
        $key = $key ?: $this->key;

        if ($signer instanceof Signer) {
            $signer->modifyHeader($this->headers);
        }

        $headers = new DataSet(
            $this->headers,
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->convertItems($this->headers)))
        );

        $claims = new DataSet(
            $this->claims,
            $this->encoder->base64UrlEncode($this->encoder->jsonEncode($this->convertItems($this->claims)))
        );

        return new Token(
            $headers,
            $claims,
            $this->createSignature($headers->toString() . '.' . $claims->toString(), $signer, $key),
            ['', ''],
            $this->claimFactory
        );
    }

    /**
     * @param array<string, mixed> $items
     *
     * @return array<string, mixed>
     */
    private function convertItems(array $items)
    {
        foreach (RegisteredClaims::DATE_CLAIMS as $name) {
            if (! array_key_exists($name, $items) || ! $items[$name] instanceof DateTimeImmutable) {
                continue;
            }

            $items[$name] = $items[$name]->getTimestamp();
        }

        if (array_key_exists(RegisteredClaims::AUDIENCE, $items) && is_array($items[RegisteredClaims::AUDIENCE])) {
            $items[RegisteredClaims::AUDIENCE] = current($items[RegisteredClaims::AUDIENCE]);
        }

        return $items;
    }

    /**
     * @param string $payload
     *
     * @return Signature
     */
    private function createSignature($payload, Signer $signer = null, Key $key = null)
    {
        if ($signer === null || $key === null) {
            return Signature::fromEmptyData();
        }

        $hash = $signer->sign($payload, $key)->hash();

        return new Signature($hash, $this->encoder->base64UrlEncode($hash));
    }
}
