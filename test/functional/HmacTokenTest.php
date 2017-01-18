<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class HmacTokenTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Configuration
     */
    private $config;

    /**
     * @before
     */
    public function createConfiguration(): void
    {
        $this->config = new Configuration();
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function builderCanGenerateAToken(): Token
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->identifiedBy('1')
                         ->canOnlyBeUsedBy('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->with('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($this->config->getSigner(), new Key('testing'));

        self::assertAttributeInstanceOf(Signature::class, 'signature', $token);
        self::assertEquals('1234', $token->headers()->get('jki'));
        self::assertEquals(['http://client.abc.com'], $token->claims()->get('aud'));
        self::assertEquals('http://api.abc.com', $token->claims()->get('iss'));
        self::assertEquals($user, $token->claims()->get('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     */
    public function parserCanReadAToken(Token $generated): void
    {
        $read = $this->config->getParser()->parse((string) $generated);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->claims()->get('user')['name']);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @expectedException \Lcobucci\JWT\Validation\InvalidTokenException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRight(Token $token): void
    {
        $this->config->getValidator()->assert(
            $token,
            new SignedWith($this->config->getSigner(), new Key('testing1'))
        );
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @expectedException \Lcobucci\JWT\Validation\InvalidTokenException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha512
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureAssertionShouldRaiseExceptionWhenAlgorithmIsDifferent(Token $token): void
    {
        $this->config->getValidator()->assert(
            $token,
            new SignedWith(new Sha512(), new Key('testing'))
        );
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith($this->config->getSigner(), new Key('testing'));

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = $this->config->getParser()->parse((string) $data);
        $constraint = new SignedWith($this->config->getSigner(), new Key('testing'));

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
        self::assertEquals('world', $token->claims()->get('hello'));
    }
}
