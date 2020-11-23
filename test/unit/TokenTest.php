<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use DateTime;
use DateTimeImmutable;
use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Token\RegisteredClaims;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass \Lcobucci\JWT\Token
 *
 * @covers \Lcobucci\JWT\Token\DataSet
 *
 * @uses \Lcobucci\JWT\Claim\Factory
 * @uses \Lcobucci\JWT\Claim\EqualsTo
 * @uses \Lcobucci\JWT\Claim\Basic
 */
class TokenTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::getHeaders
     * @covers ::getClaims
     * @covers ::signature
     * @covers ::getPayload
     */
    public function constructMustInitializeAnEmptyPlainTextTokenWhenNoArgumentsArePassed()
    {
        $token = new Token();

        $this->assertEquals(['alg' => 'none'], $token->getHeaders());
        $this->assertEquals([], $token->getClaims());
        $this->assertNull($token->signature());
        $this->assertEquals('.', $token->getPayload());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::hasHeader
     */
    public function hasHeaderMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertTrue($token->hasHeader('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::hasHeader
     */
    public function hasHeaderMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertFalse($token->hasHeader('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers ::getHeader
     *
     * @expectedException \OutOfBoundsException
     * @expectedExceptionMessageRegExp /testing/
     */
    public function getHeaderMustRaiseExceptionWhenHeaderIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $token->getHeader('testing');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers ::getHeader
     */
    public function getHeaderMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals('blah', $token->getHeader('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers ::getHeader
     */
    public function getHeaderMustReturnTheRequestedHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals('testing', $token->getHeader('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::getHeader
     */
    public function getHeaderMustReturnValueWhenItIsAReplicatedClaim()
    {
        $token = new Token(['jti' => 1]);

        $this->assertEquals(1, $token->getHeader('jti'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::getHeaders
     */
    public function getHeadersMustReturnTheConfiguredHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getHeaders());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::getClaims
     */
    public function getClaimsMustReturnTheConfiguredClaims()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getClaims());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::hasClaim
     */
    public function hasClaimMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertTrue($token->hasClaim('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::hasClaim
     */
    public function hasClaimMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertFalse($token->hasClaim('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::getClaim
     */
    public function getClaimMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertEquals('blah', $token->getClaim('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::getClaim
     *
     * @expectedException \OutOfBoundsException
     * @expectedExceptionMessageRegExp /testing/
     */
    public function getClaimShouldRaiseExceptionWhenClaimIsNotConfigured()
    {
        $token = new Token();
        $token->getClaim('testing');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::getClaim
     */
    public function getClaimShouldReturnNullValueWhenDefaultParameterIsPassed()
    {
        $token = new Token();
        self::assertNull($token->getClaim('testing', null));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     *
     * @covers ::getClaim
     */
    public function getClaimShouldReturnTheClaimValueWhenItExists()
    {
        $token = new Token([], ['testing' => 'test']);

        $this->assertEquals('test', $token->getClaim('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::verify
     *
     * @expectedException BadMethodCallException
     */
    public function verifyMustRaiseExceptionWhenTokenIsUnsigned()
    {
        $signer = $this->createMock(Signer::class);

        $token = new Token();
        $token->verify($signer, 'test');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::verify
     * @covers ::getPayload
     */
    public function verifyShouldReturnFalseWhenTokenAlgorithmIsDifferent()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->never())
                  ->method('verify');

        $token = new Token(['alg' => 'RS256'], [], $signature);

        $this->assertFalse($token->verify($signer, 'test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::verify
     * @covers ::getPayload
     */
    public function verifyMustDelegateTheValidationToSignature()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->once())
                  ->method('verify')
                  ->with($signer, $this->isType('string'), 'test')
                  ->willReturn(true);

        $token = new Token(['alg' => 'HS256'], [], $signature);

        $this->assertTrue($token->verify($signer, 'test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setCurrentTime
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenClaimsAreEmpty()
    {
        $token = new Token();

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setCurrentTime
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoValidatableClaims()
    {
        $token = new Token([], ['testing' => 'test']);

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\EqualsTo
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnFalseWhenThereIsAtLeastOneFailedValidatableClaim()
    {
        $token = new Token(
            [],
            [
                'iss' => 'test',
                'testing' => 'test',
            ]
        );

        $data = new ValidationData();
        $data->setIssuer('test1');

        $this->assertFalse($token->validate($data));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\EqualsTo
     * @uses Lcobucci\JWT\Claim\LesserOrEqualsTo
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnFalseWhenATimeBasedClaimFails()
    {
        $now = new DateTimeImmutable();

        $token = new Token(
            [],
            [
                'iss' => 'test',
                'iat' => $now,
                'nbf' => $now->modify('+20 seconds'),
                'exp' => $now->modify('+500 seconds'),
                'testing' => 'test',
            ]
        );

        $data = new ValidationData($now->modify('+10 seconds')->getTimestamp());
        $data->setIssuer('test');

        $this->assertFalse($token->validate($data));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\EqualsTo
     * @uses Lcobucci\JWT\Claim\LesserOrEqualsTo
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoFailedValidatableClaims()
    {
        $now = new DateTimeImmutable();

        $token = new Token(
            [],
            [
                'iss' => 'test',
                'iat' => $now,
                'exp' => $now->modify('+500 seconds'),
                'testing' => 'test',
            ]
        );

        $data = new ValidationData($now->modify('+10 seconds')->getTimestamp());
        $data->setIssuer('test');

        $this->assertTrue($token->validate($data));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\EqualsTo
     * @uses Lcobucci\JWT\Claim\LesserOrEqualsTo
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo
     *
     * @covers ::validate
     * @covers ::getClaims
     * @covers ::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenLeewayMakesAllTimeBasedClaimsTrueAndOtherClaimsAreTrue()
    {
        $now = new DateTimeImmutable();

        $token = new Token(
            [],
            [
                'iss' => 'test',
                'iat' => $now,
                'nbf' => $now->modify('+20 seconds'),
                'exp' => $now->modify('+500 seconds'),
                'testing' => 'test'
            ]
        );

        $data = new ValidationData($now->modify('+10 seconds')->getTimestamp(), 20);
        $data->setIssuer('test');

        $this->assertTrue($token->validate($data));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isPermittedForShouldReturnFalseWhenNoAudienceIsConfigured()
    {
        $token = new Token();

        self::assertFalse($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isPermittedForShouldReturnFalseWhenAudienceDoesNotMatch()
    {
        $token = new Token(
            [],
            [RegisteredClaims::AUDIENCE => 'test']
        );

        self::assertFalse($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isPermittedForShouldReturnFalseWhenAudienceTypeDoesNotMatch()
    {
        $token = new Token(
            [],
            [RegisteredClaims::AUDIENCE => 10]
        );

        self::assertFalse($token->isPermittedFor('10'));
    }

    /**
     * @test
     *
     * @covers ::isPermittedFor
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isPermittedForShouldReturnTrueWhenAudienceMatches()
    {
        $token = new Token(
            [],
            [RegisteredClaims::AUDIENCE => 'testing']
        );

        self::assertTrue($token->isPermittedFor('testing'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isIdentifiedByShouldReturnFalseWhenNoIdWasConfigured()
    {
        $token = new Token();

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isIdentifiedByShouldReturnFalseWhenIdDoesNotMatch()
    {
        $token = new Token(
            [],
            [RegisteredClaims::ID => 'testing']
        );

        self::assertFalse($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isIdentifiedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isIdentifiedByShouldReturnTrueWhenIdMatches()
    {
        $token = new Token(
            [],
            [RegisteredClaims::ID => 'test']
        );

        self::assertTrue($token->isIdentifiedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isRelatedToShouldReturnFalseWhenNoSubjectWasConfigured()
    {
        $token = new Token();

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isRelatedToShouldReturnFalseWhenSubjectDoesNotMatch()
    {
        $token = new Token(
            [],
            [RegisteredClaims::SUBJECT => 'testing']
        );

        self::assertFalse($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::isRelatedTo
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isRelatedToShouldReturnTrueWhenSubjectMatches()
    {
        $token = new Token(
            [],
            [RegisteredClaims::SUBJECT => 'test']
        );

        self::assertTrue($token->isRelatedTo('test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotConfigured()
    {
        $token = new Token();

        self::assertFalse($token->hasBeenIssuedBy('test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerTypeDoesNotMatches()
    {
        $token = new Token(
            [],
            [RegisteredClaims::ISSUER => 10]
        );

        self::assertFalse($token->hasBeenIssuedBy('10'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedByShouldReturnFalseWhenIssuerIsNotInTheGivenList()
    {
        $token = new Token(
            [],
            [RegisteredClaims::ISSUER => 'test']
        );

        self::assertFalse($token->hasBeenIssuedBy('testing1', 'testing2'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBy
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedByShouldReturnTrueWhenIssuerIsInTheGivenList()
    {
        $token = new Token(
            [],
            [RegisteredClaims::ISSUER => 'test']
        );

        self::assertTrue($token->hasBeenIssuedBy('testing1', 'testing2', 'test'));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured()
    {
        $token = new Token();

        self::assertTrue($token->hasBeenIssuedBefore(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsBeforeThanNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::ISSUED_AT => $now->modify('-100 seconds')]
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedBeforeShouldReturnTrueWhenIssueTimeIsEqualsToNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::ISSUED_AT => $now]
        );

        self::assertTrue($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::hasBeenIssuedBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function hasBeenIssuedBeforeShouldReturnFalseWhenIssueTimeIsGreaterThanNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::ISSUED_AT => $now->modify('+100 seconds')]
        );

        self::assertFalse($token->hasBeenIssuedBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenIssueTimeIsNotConfigured()
    {
        $token = new Token();

        self::assertTrue($token->isMinimumTimeBefore(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsBeforeThanNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::NOT_BEFORE => $now->modify('-100 seconds')]
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isMinimumTimeBeforeShouldReturnTrueWhenNotBeforeClaimIsEqualsToNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::NOT_BEFORE => $now]
        );

        self::assertTrue($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isMinimumTimeBefore
     *
     * @uses \Lcobucci\JWT\Token::__construct
     */
    public function isMinimumTimeBeforeShouldReturnFalseWhenNotBeforeClaimIsGreaterThanNow()
    {
        $now   = new DateTimeImmutable();
        $token = new Token(
            [],
            [RegisteredClaims::NOT_BEFORE => $now->modify('100 seconds')]
        );

        self::assertFalse($token->isMinimumTimeBefore($now));
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires()
    {
        $token = new Token(['alg' => 'none']);

        $this->assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => new DateTimeImmutable('+500 seconds')]
        );

        $this->assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers ::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => new DateTimeImmutable()]
        );

        $this->assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers ::getPayload
     */
    public function getPayloadShouldReturnAStringWithTheTwoEncodePartsThatGeneratedTheToken()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test1', 'test2', 'test3']);

        $this->assertEquals('test1.test2', $token->getPayload());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getPayload
     *
     * @covers ::__toString
     * @covers ::toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test', 'test']);

        $this->assertEquals('test.test.', (string) $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getPayload
     *
     * @covers ::__toString
     * @covers ::toString
     */
    public function toStringMustReturnEncodedData()
    {
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $token = new Token(['alg' => 'none'], [], $signature, ['test', 'test', 'test']);

        $this->assertEquals('test.test.test', (string) $token);
    }
}
