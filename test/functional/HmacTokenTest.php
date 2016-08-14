<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Token;

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
    public function createConfiguration()
    {
        $this->config = new Configuration();
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->setId('1')
                         ->setAudience('http://client.abc.com')
                         ->setIssuer('http://api.abc.com')
                         ->set('user', $user)
                         ->setHeader('jki', '1234')
                         ->sign($this->config->getSigner(), 'testing')
                         ->getToken();

        $this->assertAttributeInstanceOf(Signature::class, 'signature', $token);
        $this->assertEquals('1234', $token->getHeader('jki'));
        $this->assertEquals(['http://client.abc.com'], $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
        $this->assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = $this->config->getParser()->parse((string) $generated);

        $this->assertEquals($generated, $read);
        $this->assertEquals('testing', $read->getClaim('user')['name']);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->assertFalse($token->verify($this->config->getSigner(), 'testing1'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Lcobucci\JWT\Signer\Hmac\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), 'testing'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->assertTrue($token->verify($this->config->getSigner(), 'testing'));
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Configuration
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = $this->config->getParser()->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify($this->config->getSigner(), 'testing'));
    }
}
