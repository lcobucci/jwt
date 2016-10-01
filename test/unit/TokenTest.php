<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTime;
use Lcobucci\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class TokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token::__construct
     */
    public function constructMustInitializeAnEmptyPlainTextTokenWhenNoArgumentsArePassed()
    {
        $token = new Token();

        self::assertAttributeEquals(['alg' => 'none'], 'headers', $token);
        self::assertAttributeEquals([], 'claims', $token);
        self::assertAttributeEquals(null, 'signature', $token);
        self::assertAttributeEquals(['', ''], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::hasHeader
     */
    public function hasHeaderMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token(['test' => 'testing']);

        self::assertTrue($token->hasHeader('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::hasHeader
     */
    public function hasHeaderMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        self::assertFalse($token->hasHeader('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers \Lcobucci\JWT\Token::getHeader
     *
     * @expectedException \OutOfBoundsException
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
     * @covers \Lcobucci\JWT\Token::getHeader
     */
    public function getHeaderMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token(['test' => 'testing']);

        self::assertEquals('blah', $token->getHeader('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers \Lcobucci\JWT\Token::getHeader
     */
    public function getHeaderMustReturnTheRequestedHeader()
    {
        $token = new Token(['test' => 'testing']);

        self::assertEquals('testing', $token->getHeader('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasHeader
     *
     * @covers \Lcobucci\JWT\Token::getHeader
     */
    public function getHeaderMustReturnValueWhenItIsAReplicatedClaim()
    {
        $token = new Token(['jti' => 1]);

        self::assertEquals(1, $token->getHeader('jti'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::getHeaders
     */
    public function getHeadersMustReturnTheConfiguredHeader()
    {
        $token = new Token(['test' => 'testing']);

        self::assertEquals(['test' => 'testing'], $token->getHeaders());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::getClaims
     */
    public function getClaimsMustReturnTheConfiguredClaims()
    {
        $token = new Token([], ['test' => 'testing']);

        self::assertEquals(['test' => 'testing'], $token->getClaims());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::hasClaim
     */
    public function hasClaimMustReturnTrueWhenItIsConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        self::assertTrue($token->hasClaim('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::hasClaim
     */
    public function hasClaimMustReturnFalseWhenItIsNotConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        self::assertFalse($token->hasClaim('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     *
     * @covers \Lcobucci\JWT\Token::getClaim
     */
    public function getClaimMustReturnTheDefaultValueWhenIsNotConfigured()
    {
        $token = new Token([], ['test' => 'testing']);

        self::assertEquals('blah', $token->getClaim('testing', 'blah'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::hasClaim
     *
     * @covers \Lcobucci\JWT\Token::getClaim
     *
     * @expectedException \OutOfBoundsException
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
     *
     * @covers \Lcobucci\JWT\Token::getClaim
     */
    public function getClaimShouldReturnTheClaimValueWhenItExists()
    {
        $token = new Token([], ['testing' => 'test']);

        self::assertEquals('test', $token->getClaim('testing'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Token::verify
     */
    public function verifyShouldReturnFalseWhenTokenIsUnsigned()
    {
        $signer = $this->createMock(Signer::class);

        $token = new Token();

        self::assertFalse($token->verify($signer, new Key('test')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Token::verify
     * @covers \Lcobucci\JWT\Token::getPayload
     */
    public function verifyShouldReturnFalseWhenTokenAlgorithmIsDifferent()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class);

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->never())
                  ->method('verify');

        $token = new Token(['alg' => 'RS256'], [], $signature);

        self::assertFalse($token->verify($signer, new Key('test')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Token::verify
     * @covers \Lcobucci\JWT\Token::getPayload
     */
    public function verifyMustDelegateTheValidationToSignature()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class);
        $key = new Key('test');

        $signer->expects($this->any())
               ->method('getAlgorithmId')
               ->willReturn('HS256');

        $signature->expects($this->once())
                  ->method('verify')
                  ->with($signer, $this->isType('string'), $key)
                  ->willReturn(true);

        $token = new Token(['alg' => 'HS256'], [], $signature);

        self::assertTrue($token->verify($signer, $key));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnFalseWhenTokenDoesNotExpires()
    {
        $token = new Token(['alg' => 'none']);

        self::assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnFalseWhenTokenIsNotExpired()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => time() + 500]
        );

        self::assertFalse($token->isExpired());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnFalseWhenExpirationIsEqualsToNow()
    {
        $now = new DateTime();

        $token = new Token(
            ['alg' => 'none'],
            ['exp' => $now->getTimestamp()]
        );

        self::assertFalse($token->isExpired($now));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token::isExpired
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getClaim
     * @uses \Lcobucci\JWT\Token::hasClaim
     */
    public function isExpiredShouldReturnTrueAfterTokenExpires()
    {
        $token = new Token(
            ['alg' => 'none'],
            ['exp' => time()]
        );

        self::assertTrue($token->isExpired(new DateTime('+10 days')));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Token::getPayload
     */
    public function getPayloadShouldReturnAStringWithTheTwoEncodePartsThatGeneratedTheToken()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test1', 'test2', 'test3']);

        self::assertEquals('test1.test2', $token->getPayload());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getPayload
     *
     * @covers \Lcobucci\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test', 'test']);

        self::assertEquals('test.test.', (string) $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Token::getPayload
     *
     * @covers \Lcobucci\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedData()
    {
        $signature = $this->createMock(Signature::class);

        $token = new Token(['alg' => 'none'], [], $signature, ['test', 'test', 'test']);

        self::assertEquals('test.test.test', (string) $token);
    }
}
