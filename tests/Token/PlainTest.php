<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Lcobucci\JWT\Token\Plain
 *
 * @uses \Lcobucci\JWT\Token\Plain::__construct
 * @uses \Lcobucci\JWT\Token\Plain::payload
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class PlainTest extends TestCase
{
    private DataSet $headers;
    private DataSet $claims;
    private Signature $signature;

    /** @before */
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

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::headers
     * @covers ::claims
     * @covers ::signature
     */
    public function signedShouldCreateATokenWithSignature(): void
    {
        $token = $this->createToken();

        self::assertSame($this->headers, $token->headers());
        self::assertSame($this->claims, $token->claims());
        self::assertSame($this->signature, $token->signature());
    }

    /**
     * @test
     *
     * @covers ::payload
     */
    public function payloadShouldReturnAStringWithTheEncodedHeadersAndClaims(): void
    {
        $token = $this->createToken();

        self::assertSame('headers.claims', $token->payload());
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     */
    public function isPermittedForShouldReturnFalseWhenNoAudienceIsConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     */
    public function isPermittedForShouldReturnFalseWhenAudienceDoesNotMatchAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['test', 'test2']], ''),
        );

        self::assertFalse($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     */
    public function isPermittedForShouldReturnFalseWhenAudienceTypeDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => [10]], ''),
        );

        self::assertFalse($token->isPermittedFor('10'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     */
    public function isPermittedForShouldReturnTrueWhenAudienceMatchesAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['testing', 'test']], ''),
        );

        self::assertTrue($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     */
    public function isIdentifiedByShouldReturnFalseWhenNoIdWasConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     */
    public function isIdentifiedByShouldReturnFalseWhenIdDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'testing'], ''),
        );

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     */
    public function isIdentifiedByShouldReturnTrueWhenIdMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'test'], ''),
        );

        self::assertTrue($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     */
    public function isRelatedToShouldReturnFalseWhenNoSubjectWasConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     */
    public function isRelatedToShouldReturnFalseWhenSubjectDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'testing'], ''),
        );

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     */
    public function isRelatedToShouldReturnTrueWhenSubjectMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'test'], ''),
        );

        self::assertTrue($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->hasBeenIssuedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerTypeDoesNotMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 10], ''),
        );

        self::assertFalse($token->hasBeenIssuedBy('10'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], ''),
        );

        self::assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     */
    public function hasBeenIssuedByShouldReturnTrueWhenIssuerIsInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], ''),
        );

        self::assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->hasBeenIssuedBefore(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('-100 seconds')], ''),
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now], ''),
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     */
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('+100 seconds')], ''),
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->isMinimumTimeBefore(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('-100 seconds')], ''),
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now], ''),
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     */
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('100 seconds')], ''),
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isExpired(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now->modify('+500 seconds')], ''),
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     */
    public function isExpiredShouldReturnTrueWhenExpirationIsEqualsToNow(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        self::assertTrue($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], ''),
        );

        self::assertTrue($token->isExpired($now->modify('+10 days')));
    }

    /**
     * @test
     *
     * @covers ::toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature(): void
    {
        $token = $this->createToken(null, null, new Signature('123', '456'));

        self::assertSame('headers.claims.456', $token->toString());
    }

    /**
     * @test
     *
     * @covers ::toString
     */
    public function toStringMustReturnEncodedData(): void
    {
        $token = $this->createToken();

        self::assertSame('headers.claims.signature', $token->toString());
    }
}
