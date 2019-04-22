<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Plain;

interface Builder
{
    /**
     * Appends new items to audience
     */
    public function permittedFor(string ...$audiences): Builder;

    /**
     * Configures the expiration time
     */
    public function expiresAt(DateTimeImmutable $expiration): Builder;

    /**
     * Configures the token id
     */
    public function identifiedBy(string $id): Builder;

    /**
     * Configures the time that the token was issued
     */
    public function issuedAt(DateTimeImmutable $issuedAt): Builder;

    /**
     * Configures the issuer
     */
    public function issuedBy(string $issuer): Builder;

    /**
     * Configures the time before which the token cannot be accepted
     */
    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): Builder;

    /**
     * Configures the subject
     */
    public function relatedTo(string $subject): Builder;

    /**
     * Configures a header item
     *
     * @param mixed $value
     */
    public function withHeader(string $name, $value): Builder;

    /**
     * Configures a claim item
     *
     * @param mixed $value
     *
     * @throws InvalidArgumentException When trying to set a registered claim.
     */
    public function withClaim(string $name, $value): Builder;

    /**
     * Returns a signed token to be used
     */
    public function getToken(Signer $signer, Key $key): Plain;
}
