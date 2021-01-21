<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Token\Plain */
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
        ?Signature $signature = null
    ): Plain {
        return new Plain(
            $headers ?? $this->headers,
            $claims ?? $this->claims,
            $signature ?? $this->signature
        );
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::headers
     * @covers ::claims
     * @covers ::signature
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isPermittedForShouldReturnFalseWhenAudienceDoesNotMatchAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['test', 'test2']], '')
        );

        self::assertFalse($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isPermittedForShouldReturnFalseWhenAudienceTypeDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => [10]], '')
        );

        self::assertFalse($token->isPermittedFor('10'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isPermittedForShouldReturnTrueWhenAudienceMatchesAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['testing', 'test']], '')
        );

        self::assertTrue($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isIdentifiedByShouldReturnFalseWhenIdDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'testing'], '')
        );

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isIdentifiedByShouldReturnTrueWhenIdMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ID => 'test'], '')
        );

        self::assertTrue($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isRelatedToShouldReturnFalseWhenSubjectDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'testing'], '')
        );

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isRelatedToShouldReturnTrueWhenSubjectMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::SUBJECT => 'test'], '')
        );

        self::assertTrue($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerTypeDoesNotMatches(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 10], '')
        );

        self::assertFalse($token->hasBeenIssuedBy('10'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], '')
        );

        self::assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedByShouldReturnTrueWhenIssuerIsInTheGivenList(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUER => 'test'], '')
        );

        self::assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('-100 seconds')], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->modify('+100 seconds')], '')
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('-100 seconds')], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow(): void
    {
        $now   = new DateTimeImmutable();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->modify('100 seconds')], '')
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
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
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now->modify('+500 seconds')], '')
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnTrueWhenExpirationIsEqualsToNow(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], '')
        );

        self::assertTrue($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires(): void
    {
        $now = new DateTimeImmutable();

        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now], '')
        );

        self::assertTrue($token->isExpired($now->modify('+10 days')));
    }

    /**
     * @test
     *
     * @covers ::toString
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::payload
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function toStringMustReturnEncodedDataWithEmptySignature(): void
    {
        $token = $this->createToken(null, null, Signature::fromEmptyData());

        self::assertSame('headers.claims.', $token->toString());
    }

    /**
     * @test
     *
     * @covers ::toString
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function toStringMustReturnEncodedData(): void
    {
        $token = $this->createToken();

        self::assertSame('headers.claims.signature', $token->toString());
    }
}
