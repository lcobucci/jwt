<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha512;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;

class RsaTokenTest extends TestCase
{
    use Keys;

    /**
     * @var Configuration
     */
    private $config;

    /**
     * @before
     */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Sha256(),
            static::$rsaKeys['private'],
            static::$rsaKeys['public']
        );
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->permittedFor('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->getSigner(), new Key('testing'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsNotRsaCompatible(): void
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->permittedFor('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->getSigner(), static::$ecdsaKeys['private']);
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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     */
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->identifiedBy('1')
                         ->permittedFor('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->withClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($this->config->getSigner(), $this->config->getSigningKey());

        self::assertAttributeInstanceOf(Signature::class, 'signature', $token);
        self::assertEquals('1234', $token->headers()->get('jki'));
        self::assertEquals(['http://client.abc.com'], $token->claims()->get(Token\RegisteredClaims::AUDIENCE));
        self::assertEquals('http://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
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
        /** @var Token\Plain $read */
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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRight(Token $token): void
    {
        $this->config->getValidator()->assert(
            $token,
            new SignedWith($this->config->getSigner(), self::$rsaKeys['encrypted-public'])
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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha512
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\InvalidTokenException
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureAssertionShouldRaiseExceptionWhenAlgorithmIsDifferent(Token $token): void
    {
        $this->config->getValidator()->assert(
            $token,
            new SignedWith(new Sha512(), $this->config->getVerificationKey())
        );
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRsaCompatible(Token $token): void
    {
        $this->config->getValidator()->assert(
            $token,
            new SignedWith(
                $this->config->getSigner(),
                self::$ecdsaKeys['public1']
            )
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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith($this->config->getSigner(), $this->config->getVerificationKey());

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
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\Rsa
     * @covers \Lcobucci\JWT\Signer\Rsa\Sha256
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $data = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.s'
                . 'GYbB1KrmnESNfJ4D9hOe1Zad_BMyxdb8G4p4LNP7StYlOyBWck6q7XPpPj_6gB'
                . 'Bo1ohD3MA2o0HY42lNIrAStaVhfsFKGdIou8TarwMGZBPcif_3ThUV1pGS3fZc'
                . 'lFwF2SP7rqCngQis_xcUVCyqa8E1Wa_v28grnl1QZrnmQFO8B5JGGLqcrfUHJO'
                . 'nJCupP-Lqh4TmIhftIimSCgLNmJg80wyrpUEfZYReE7hPuEmY0ClTqAGIMQoNS'
                . '98ljwDxwhfbSuL2tAdbV4DekbTpWzspe3dOJ7RSzmPKVZ6NoezaIazKqyqkmHZfcMaHI1lQeGia6LTbHU1bp0gINi74Vw';

        /** @var Token\Plain $token */
        $token      = $this->config->getParser()->parse($data);
        $constraint = new SignedWith($this->config->getSigner(), $this->config->getVerificationKey());

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
        self::assertEquals('world', $token->claims()->get('hello'));
    }
}
