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
     * @before
     */
    public function createDependencies()
    {
        $this->headers = new DataSet(['alg' => 'none'],  'headers');
        $this->claims = new DataSet([],  'claims');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::__construct
     * @covers \Lcobucci\JWT\Token\Plain::unsecured
     */
    public function unsecuredShouldCreateATokenWithoutSignature()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertAttributeSame($this->headers, 'headers', $token);
        self::assertAttributeSame($this->claims, 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::__construct
     * @covers \Lcobucci\JWT\Token\Plain::signed
     */
    public function signedShouldCreateATokenWithSignature()
    {
        $signature = new Signature('hash', 'signature');
        $token = Plain::signed($this->headers, $this->claims, $signature);

        self::assertAttributeSame($this->headers, 'headers', $token);
        self::assertAttributeSame($this->claims, 'claims', $token);
        self::assertAttributeSame($signature, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::headers
     */
    public function headersMustReturnTheConfiguredDataSet()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertSame($this->headers, $token->headers());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::claims
     */
    public function claimsMustReturnTheConfiguredClaims()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertSame($this->claims, $token->claims());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::signature
     */
    public function signatureShouldReturnNullWhenSignatureIsNotConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertNull($token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::signed
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::signature
     */
    public function signatureShouldReturnTheConfiguredSignature()
    {
        $signature = new Signature('hash', 'signature');
        $token = Plain::signed($this->headers, $this->claims, $signature);

        self::assertSame($signature, $token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::payload
     */
    public function payloadShouldReturnAStringWithTheEncodedHeadersAndClaims()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertEquals('headers.claims', $token->payload());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnFalseWhenNoAudienceIsConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnFalseWhenAudienceDoesNotMatchAsString()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['aud' => 'test'], '')
        );

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnFalseWhenAudienceDoesNotMatchAsArray()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['aud' => ['test', 'test2']], '')
        );

        self::assertFalse($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnFalseWhenAudienceTypeDoesNotMatch()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['aud' => 10], '')
        );

        self::assertFalse($token->isAllowedTo('10'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnTrueWhenAudienceMatchesAsString()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['aud' => 'testing'], '')
        );

        self::assertTrue($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isAllowedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isAllowedToShouldReturnTrueWhenAudienceMatchesAsArray()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['aud' => ['testing', 'test']], '')
        );

        self::assertTrue($token->isAllowedTo('testing'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isIdentifiedByShouldReturnFalseWhenNoIdWasConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isIdentifiedByShouldReturnFalseWhenIdDoesNotMatch()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['jti' => 'testing'], '')
        );

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isIdentifiedByShouldReturnTrueWhenIdMatches()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['jti' => 'test'], '')
        );

        self::assertTrue($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isRelatedToShouldReturnFalseWhenNoSubjectWasConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isRelatedToShouldReturnFalseWhenSubjectDoesNotMatch()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['sub' => 'testing'], '')
        );

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isRelatedToShouldReturnTrueWhenSubjectMatches()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['sub' => 'test'], '')
        );

        self::assertTrue($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertFalse($token->hasBeenIssuedBy('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerTypeDoesNotMatches()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iss' => 10], '')
        );

        self::assertFalse($token->hasBeenIssuedBy('10'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotInTheGivenList()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iss' => 'test'], '')
        );

        self::assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedByShouldReturnTrueWhenIssuerIsInTheGivenList()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iss' => 'test'], '')
        );

        self::assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertTrue($token->hasBeenIssuedBefore(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iat' => $now->getTimestamp() - 100], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iat' => $now->getTimestamp()], '')
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['iat' => $now->getTimestamp() + 100], '')
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertTrue($token->isMinimumTimeBefore(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['nbf' => $now->getTimestamp() - 100], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['nbf' => $now->getTimestamp()], '')
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['nbf' => $now->getTimestamp() + 100], '')
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertFalse($token->isExpired(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['exp' => time() + 500], '')
        );

        self::assertFalse($token->isExpired(new DateTime()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isExpiredShouldReturnFalseWhenExpirationIsEqualsToNow()
    {
        $now = new DateTime();
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['exp' => $now->getTimestamp()], '')
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Plain::isExpired
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires()
    {
        $token = Plain::unsecured(
            $this->headers,
            new DataSet(['exp' => time()], '')
        );

        self::assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::unsecured
     * @uses \Lcobucci\JWT\Token\Plain::payload
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Plain::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = Plain::unsecured($this->headers, $this->claims);

        self::assertEquals('headers.claims.', (string) $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Plain::__construct
     * @uses \Lcobucci\JWT\Token\Plain::signed
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Token\Signature
     *
     * @covers \Lcobucci\JWT\Token\Plain::__toString
     */
    public function toStringMustReturnEncodedData()
    {
        $token = Plain::signed(
            $this->headers,
            $this->claims,
            new Signature('hash', 'signature')
        );

        self::assertEquals('headers.claims.signature', (string) $token);
    }
}
