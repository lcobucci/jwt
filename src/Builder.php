<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\CannotEncodeContent;
use Lcobucci\JWT\Signer\CannotSignPayload;
use Lcobucci\JWT\Signer\Ecdsa\ConversionFailed;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\RegisteredClaimGiven;
use NoDiscard;

/** @immutable */
interface Builder
{
    /**
     * Appends new items to audience
     *
     * @param non-empty-string ...$audiences
     */
    #[NoDiscard]
    public function permittedFor(string ...$audiences): Builder;

    /**
     * Configures the expiration time
     */
    #[NoDiscard]
    public function expiresAt(DateTimeImmutable $expiration): Builder;

    /**
     * Configures the token id
     *
     * @param non-empty-string $id
     */
    #[NoDiscard]
    public function identifiedBy(string $id): Builder;

    /**
     * Configures the time that the token was issued
     */
    #[NoDiscard]
    public function issuedAt(DateTimeImmutable $issuedAt): Builder;

    /**
     * Configures the issuer
     *
     * @param non-empty-string $issuer
     */
    #[NoDiscard]
    public function issuedBy(string $issuer): Builder;

    /**
     * Configures the time before which the token cannot be accepted
     */
    #[NoDiscard]
    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): Builder;

    /**
     * Configures the subject
     *
     * @param non-empty-string $subject
     */
    #[NoDiscard]
    public function relatedTo(string $subject): Builder;

    /**
     * Configures a header item
     *
     * @param non-empty-string $name
     */
    #[NoDiscard]
    public function withHeader(string $name, mixed $value): Builder;

    /**
     * Configures a claim item
     *
     * @param non-empty-string $name
     *
     * @throws RegisteredClaimGiven When trying to set a registered claim.
     */
    #[NoDiscard]
    public function withClaim(string $name, mixed $value): Builder;

    /**
     * Returns a signed token to be used
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     * @throws CannotSignPayload   When payload signing fails.
     * @throws InvalidKeyProvided  When issue key is invalid/incompatible.
     * @throws ConversionFailed    When signature could not be converted.
     */
    #[NoDiscard]
    public function getToken(Signer $signer, Key $key): UnencryptedToken;
}
