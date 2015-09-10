<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Claim\EqualsTo;
use Lcobucci\JWT\Claim\GreaterOrEqualsTo;
use Lcobucci\JWT\Claim\LesserOrEqualsTo;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class TokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers Lcobucci\JWT\Token::__construct
     */
    public function constructMustInitializeAnEmptyPlainTextTokenWhenNoArgumentsArePassed()
    {
        $token = new Token();

        $this->assertAttributeEquals(['alg' => 'none'], 'headers', $token);
        $this->assertAttributeEquals([], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['', ''], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::getHeader
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
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::getHeader
     */
    public function getHeaderMustReturnTheRequestedHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals('testing', $token->getHeader('test'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     *
     * @covers Lcobucci\JWT\Token::getHeader
     */
    public function getHeaderMustReturnValueWhenItIsAReplicatedClaim()
    {
        $token = new Token(['jti' => new EqualsTo('jti', 1)]);

        $this->assertEquals(1, $token->getHeader('jti'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::getHeaders
     */
    public function getHeadersMustReturnTheConfiguredHeader()
    {
        $token = new Token(['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getHeaders());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::getClaims
     */
    public function getClaimsMustReturnTheConfiguredClaims()
    {
        $token = new Token([], ['test' => 'testing']);

        $this->assertEquals(['test' => 'testing'], $token->getClaims());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers Lcobucci\JWT\Token::getClaim
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
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     *
     * @covers Lcobucci\JWT\Token::getClaim
     */
    public function getClaimShouldReturnTheClaimValueWhenItExists()
    {
        $token = new Token([], ['testing' => new Basic('testing', 'test')]);

        $this->assertEquals('test', $token->getClaim('testing'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::verify
     *
     * @expectedException BadMethodCallException
     */
    public function verifyMustRaiseExceptionWhenTokenIsUnsigned()
    {
        $signer = $this->getMock(Signer::class);

        $token = new Token();
        $token->verify($signer, 'test');
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::verify
     * @covers Lcobucci\JWT\Token::getPayload
     */
    public function verifyShouldReturnFalseWhenTokenAlgorithmIsDifferent()
    {
        $signer = $this->getMock(Signer::class);
        $signature = $this->getMock(Signature::class, [], [], '', false);

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
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::verify
     * @covers Lcobucci\JWT\Token::getPayload
     */
    public function verifyMustDelegateTheValidationToSignature()
    {
        $signer = $this->getMock(Signer::class);
        $signature = $this->getMock(Signature::class, [], [], '', false);

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
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\Token::validate
     * @covers Lcobucci\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenClaimsAreEmpty()
    {
        $token = new Token();

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     *
     * @covers Lcobucci\JWT\Token::validate
     * @covers Lcobucci\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoValidatableClaims()
    {
        $token = new Token([], ['testing' => new Basic('testing', 'test')]);

        $this->assertTrue($token->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::get
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\Claim\EqualsTo::__construct
     * @uses Lcobucci\JWT\Claim\EqualsTo::validate
     *
     * @covers Lcobucci\JWT\Token::validate
     * @covers Lcobucci\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnFalseWhenThereIsAtLeastOneFailedValidatableClaim()
    {
        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData();
        $data->setIssuer('test1');

        $this->assertFalse($token->validate($data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::get
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\Claim\EqualsTo::__construct
     * @uses Lcobucci\JWT\Claim\EqualsTo::validate
     * @uses Lcobucci\JWT\Claim\LesserOrEqualsTo::__construct
     * @uses Lcobucci\JWT\Claim\LesserOrEqualsTo::validate
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo::__construct
     * @uses Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     *
     * @covers Lcobucci\JWT\Token::validate
     * @covers Lcobucci\JWT\Token::getValidatableClaims
     */
    public function validateShouldReturnTrueWhenThereAreNoFailedValidatableClaims()
    {
        $now = time();
        $token = new Token(
            [],
            [
                'iss' => new EqualsTo('iss', 'test'),
                'iat' => new LesserOrEqualsTo('iat', $now),
                'exp' => new GreaterOrEqualsTo('ext', $now + 500),
                'testing' => new Basic('testing', 'test')
            ]
        );

        $data = new ValidationData($now + 10);
        $data->setIssuer('test');

        $this->assertTrue($token->validate($data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     *
     * @covers Lcobucci\JWT\Token::getPayload
     */
    public function getPayloadShouldReturnAStringWithTheTwoEncodePartsThatGeneratedTheToken()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test1', 'test2', 'test3']);

        $this->assertEquals('test1.test2', $token->getPayload());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Token::getPayload
     *
     * @covers Lcobucci\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedDataWithEmptySignature()
    {
        $token = new Token(['alg' => 'none'], [], null, ['test', 'test']);

        $this->assertEquals('test.test.', (string) $token);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Token::__construct
     * @uses Lcobucci\JWT\Token::getPayload
     *
     * @covers Lcobucci\JWT\Token::__toString
     */
    public function toStringMustReturnEncodedData()
    {
        $signature = $this->getMock(Signature::class, [], [], '', false);

        $token = new Token(['alg' => 'none'], [], $signature, ['test', 'test', 'test']);

        $this->assertEquals('test.test.test', (string) $token);
    }
}
