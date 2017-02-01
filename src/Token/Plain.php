<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeInterface;
use Lcobucci\JWT\Token as TokenInterface;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Plain implements TokenInterface
{
    /**
     * The token headers
     *
     * @var DataSet
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature
     */
    private $signature;

    public function __construct(
        DataSet $headers,
        DataSet $claims,
        Signature $signature
    ) {
        $this->headers = $headers;
        $this->claims = $claims;
        $this->signature = $signature;
    }

    /**
     * {@inheritdoc}
     */
    public function headers(): DataSet
    {
        return $this->headers;
    }

    /**
     * {@inheritdoc}
     */
    public function claims(): DataSet
    {
        return $this->claims;
    }

    /**
     * {@inheritdoc}
     */
    public function signature(): Signature
    {
        return $this->signature;
    }

    /**
     * {@inheritdoc}
     */
    public function payload(): string
    {
        return $this->headers . '.' . $this->claims;
    }

    /**
     * {@inheritdoc}
     */
    public function isAllowedTo(string $audience): bool
    {
        return in_array($audience, (array) $this->claims->get(RegisteredClaims::AUDIENCE), true);
    }

    /**
     * {@inheritdoc}
     */
    public function isIdentifiedBy(string $id): bool
    {
        return $this->claims->get(RegisteredClaims::ID) === $id;
    }

    /**
     * {@inheritdoc}
     */
    public function isRelatedTo(string $subject): bool
    {
        return $this->claims->get(RegisteredClaims::SUBJECT) === $subject;
    }

    /**
     * {@inheritdoc}
     */
    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        return in_array($this->claims->get(RegisteredClaims::ISSUER), $issuers, true);
    }

    /**
     * {@inheritdoc}
     */
    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
    {
        return $now->getTimestamp() >= $this->claims->get(RegisteredClaims::ISSUED_AT);
    }

    /**
     * {@inheritdoc}
     */
    public function isMinimumTimeBefore(DateTimeInterface $now): bool
    {
        return $now->getTimestamp() >= $this->claims->get(RegisteredClaims::NOT_BEFORE);
    }

    /**
     * {@inheritdoc}
     */
    public function isExpired(DateTimeInterface $now): bool
    {
        if (!$this->claims->has(RegisteredClaims::EXPIRATION_TIME)) {
            return false;
        }

        return $now->getTimestamp() > $this->claims->get(RegisteredClaims::EXPIRATION_TIME);
    }

    /**
     * {@inheritdoc}
     */
    public function __toString(): string
    {
        return implode(
            '.',
            [$this->headers, $this->claims, $this->signature]
        );
    }
}
