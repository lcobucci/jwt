<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTime;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class PlainTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var DataSet
     */
    private $headers;

    /**
     * @var DataSet
     */
    private $claims;

    /**
     * @var Signature
     */
    private $signature;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->headers = new DataSet(['alg' => 'none'],  'headers');
        $this->claims = new DataSet([],  'claims');
        $this->signature = new Signature('hash', 'signature');
    }

    private function createToken(
        DataSet $headers = null,
        DataSet $claims = null,
        Signature $signature = null
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
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::__construct
     */
    public function signedShouldCreateATokenWithSignature(): void
    {
        $token = $this->createToken();

        self::assertAttributeSame($this->headers, 'headers', $token);
        self::assertAttributeSame($this->claims, 'claims', $token);
        self::assertAttributeSame($this->signature, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::headers
     */
    public function headersMustReturnTheConfiguredDataSet(): void
    {
        $token = $this->createToken();

        self::assertSame($this->headers, $token->headers());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::claims
     */
    public function claimsMustReturnTheConfiguredClaims(): void
    {
        $token = $this->createToken();

        self::assertSame($this->claims, $token->claims());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::signature
     */
    public function signatureShouldReturnTheConfiguredSignature(): void
    {
        $token = $this->createToken();

        self::assertSame($this->signature, $token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::payload
     */
    public function payloadShouldReturnAStringWithTheEncodedHeadersAndClaims(): void
    {
        $token = $this->createToken();

        self::assertEquals('headers.claims', $token->payload());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnFalseWhenNoAudienceIsConfigured(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnFalseWhenAudienceDoesNotMatchAsString(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => 'test'], '')
        );

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnFalseWhenAudienceDoesNotMatchAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['test', 'test2']], '')
        );

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnFalseWhenAudienceTypeDoesNotMatch(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => 10], '')
        );

        self::assertFalse($token->isAllowedTo('10'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnTrueWhenAudienceMatchesAsString(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => 'testing'], '')
        );

        self::assertTrue($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isAllowedToShouldReturnTrueWhenAudienceMatchesAsArray(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::AUDIENCE => ['testing', 'test']], '')
        );

        self::assertTrue($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
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
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
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
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
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
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
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
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->hasBeenIssuedBefore(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->getTimestamp() - 100], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->getTimestamp()], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::ISSUED_AT => $now->getTimestamp() + 100], '')
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured(): void
    {
        $token = $this->createToken();

        self::assertTrue($token->isMinimumTimeBefore(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->getTimestamp() - 100], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->getTimestamp()], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::NOT_BEFORE => $now->getTimestamp() + 100], '')
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires(): void
    {
        $token = $this->createToken();

        self::assertFalse($token->isExpired(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => time() + 500], '')
        );

        self::assertFalse($token->isExpired(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnFalseWhenExpirationIsEqualsToNow(): void
    {
        $now = new DateTime();
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => $now->getTimestamp()], '')
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires(): void
    {
        $token = $this->createToken(
            null,
            new DataSet([RegisteredClaims::EXPIRATION_TIME => time()], '')
        );

        self::assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::payload
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature(): void
    {
        $token = $this->createToken(null, null, Signature::fromEmptyData());

        self::assertEquals('headers.claims.', (string) $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::__toString
     */
    public function toStringMustReturnEncodedData(): void
    {
        $token = $this->createToken();

        self::assertEquals('headers.claims.signature', (string) $token);
    }
}
