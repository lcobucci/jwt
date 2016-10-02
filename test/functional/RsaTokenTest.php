<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class RsaTokenTest extends \PHPUnit_Framework_TestCase
{
    use Keys;

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
        $this->config->setSigner(new Sha256());
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid()
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->canOnlyBeUsedBy('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->with('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->sign($this->config->getSigner(), new Key('testing'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsNotRsaCompatible()
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->canOnlyBeUsedBy('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->with('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->sign($this->config->getSigner(), static::$ecdsaKeys['private']);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->identifiedBy('1')
                         ->canOnlyBeUsedBy('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->with('user', $user)
                         ->withHeader('jki', '1234')
                         ->sign($this->config->getSigner(), static::$rsaKeys['private'])
                         ->getToken();

        self::assertAttributeInstanceOf(Signature::class, 'signature', $token);
        self::assertEquals('1234', $token->getHeader('jki'));
        self::assertEquals(['http://client.abc.com'], $token->getClaim('aud'));
        self::assertEquals('http://api.abc.com', $token->getClaim('iss'));
        self::assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = $this->config->getParser()->parse((string) $generated);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->getClaim('user')['name']);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        self::assertFalse($token->verify($this->config->getSigner(), self::$rsaKeys['encrypted-public']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        self::assertFalse($token->verify(new Sha512(), self::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldRaiseExceptionWhenKeyIsNotRsaCompatible(Token $token)
    {
        self::assertFalse($token->verify($this->config->getSigner(), self::$ecdsaKeys['public1']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        self::assertTrue($token->verify($this->config->getSigner(), self::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.s'
                . 'GYbB1KrmnESNfJ4D9hOe1Zad_BMyxdb8G4p4LNP7StYlOyBWck6q7XPpPj_6gB'
                . 'Bo1ohD3MA2o0HY42lNIrAStaVhfsFKGdIou8TarwMGZBPcif_3ThUV1pGS3fZc'
                . 'lFwF2SP7rqCngQis_xcUVCyqa8E1Wa_v28grnl1QZrnmQFO8B5JGGLqcrfUHJO'
                . 'nJCupP-Lqh4TmIhftIimSCgLNmJg80wyrpUEfZYReE7hPuEmY0ClTqAGIMQoNS'
                . '98ljwDxwhfbSuL2tAdbV4DekbTpWzspe3dOJ7RSzmPKVZ6NoezaIazKqyqkmHZfcMaHI1lQeGia6LTbHU1bp0gINi74Vw';

        $token = $this->config->getParser()->parse((string) $data);

        self::assertEquals('world', $token->getClaim('hello'));
        self::assertTrue($token->verify($this->config->getSigner(), self::$rsaKeys['public']));
    }
}
