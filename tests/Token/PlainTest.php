<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(Plain::class)]
#[PHPUnit\UsesClass(DataSet::class)]
#[PHPUnit\UsesClass(Signature::class)]
final class PlainTest extends TestCase
{
    private DataSet $headers;
    private DataSet $claims;
    private Signature $signature;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->headers   = new DataSet(['alg' => 'none'], 'headers');
        $this->claims    = new DataSet([], 'claims');
        $this->signature = new Signature('hash', 'signature');
    }

    private function createToken(
        ?DataSet $headers = null,
        ?DataSet $claims = null,
        ?Signature $signature = null,
    ): Plain {
        return new Plain(
            $headers ?? $this->headers,
            $claims ?? $this->claims,
            $signature ?? $this->signature,
        );
    }

    #[PHPUnit\Test]
    public function signedShouldCreateATokenWithSignature(): void
    {
        $token = $this->createToken();

        self::assertSame($this->headers, $token->headers());
        self::assertSame($this->claims, $token->claims());
        self::assertSame($this->signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function payloadShouldReturnAStringWithTheEncodedHeadersAndClaims(): void
    {
        $token = $this->createToken();

        self::assertSame('headers.claims', $token->payload());
    }

    #[PHPUnit\Test]
    public function isPermittedForShouldReturnFalseWhenNoAudienceIsConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isPermittedFor('testing'));
    }

    #[PHPUnit\Test]
    public function isPermittedForShouldReturnFalseWhenAudienceDoesNotMatchAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['test', 'test2']], ''),
        );

        self::assertFalse($token->isPermittedFor('testing'));
    }

    #[PHPUnit\Test]
    public function isPermittedForShouldReturnFalseWhenAudienceTypeDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => [10]], ''),
        );

        self::assertFalse($token->isPermittedFor('10'));
    }

    #[PHPUnit\Test]
    public function isPermittedForShouldReturnTrueWhenAudienceMatchesAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['testing', 'test']], ''),
        );

        self::assertTrue($token->isPermittedFor('testing'));
    }

    #[PHPUnit\Test]
    public function isIdentifiedByShouldReturnFalseWhenNoIdWasConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    #[PHPUnit\Test]
    public function isIdentifiedByShouldReturnFalseWhenIdDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'testing'], ''),
        );

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    #[PHPUnit\Test]
    public function isIdentifiedByShouldReturnTrueWhenIdMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'test'], ''),
        );

        self::assertTrue($token->isIdentifiedBy('test'));
    }

    #[PHPUnit\Test]
    public function isRelatedToShouldReturnFalseWhenNoSubjectWasConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isRelatedTo('test'));
    }

    #[PHPUnit\Test]
    public function isRelatedToShouldReturnFalseWhenSubjectDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'testing'], ''),
        );

        self::assertFalse($token->isRelatedTo('test'));
    }

    #[PHPUnit\Test]
    public function isRelatedToShouldReturnTrueWhenSubjectMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'test'], ''),
        );

        self::assertTrue($token->isRelatedTo('test'));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->hasBeenIssuedBy('test'));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerTypeDoesNotMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 10], ''),
        );

        self::assertFalse($token->hasBeenIssuedBy('10'));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], ''),
        );

        self::assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedByShouldReturnTrueWhenIssuerIsInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], ''),
        );

        self::assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->hasBeenIssuedBefore(new DateTimeImmutable()));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('-100 seconds')], ''),
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now], ''),
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    #[PHPUnit\Test]
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('+100 seconds')], ''),
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    #[PHPUnit\Test]
    public function isMinimumTimeBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->isMinimumTimeBefore(new DateTimeImmutable()));
    }

    #[PHPUnit\Test]
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('-100 seconds')], ''),
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    #[PHPUnit\Test]
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now], ''),
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    #[PHPUnit\Test]
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('100 seconds')], ''),
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    #[PHPUnit\Test]
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isExpired(new DateTimeImmutable()));
    }

    #[PHPUnit\Test]
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now->modify('+500 seconds')], ''),
        );

        self::assertFalse($token->isExpired($now));
    }

    #[PHPUnit\Test]
    public function isExpiredShouldReturnTrueWhenExpirationIsEqualsToNow(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        self::assertTrue($token->isExpired($now));
    }

    #[PHPUnit\Test]
    public function isExpiredShouldReturnTrueAfterTokenExpires(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        self::assertTrue($token->isExpired($now->modify('+10 days')));
    }

    #[PHPUnit\Test]
    public function toStringMustReturnEncodedDataWithEmptySignature(): void
    {
        $token = $this->createToken(null, null, new Signature('123', '456'));

        self::assertSame('headers.claims.456', $token->toString());
    }

    #[PHPUnit\Test]
    public function toStringMustReturnEncodedData(): void
    {
        $token = $this->createToken();

        self::assertSame('headers.claims.signature', $token->toString());
    }
}
