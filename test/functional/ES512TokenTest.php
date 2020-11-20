<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;

use function assert;

/**
 * @covers \Lcobucci\JWT\Configuration
 * @covers \Lcobucci\JWT\Encoding\JoseEncoder
 * @covers \Lcobucci\JWT\Encoding\ChainedFormatter
 * @covers \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
 * @covers \Lcobucci\JWT\Encoding\UnifyAudience
 * @covers \Lcobucci\JWT\Token\Builder
 * @covers \Lcobucci\JWT\Token\Parser
 * @covers \Lcobucci\JWT\Token\Plain
 * @covers \Lcobucci\JWT\Token\DataSet
 * @covers \Lcobucci\JWT\Token\Signature
 * @covers \Lcobucci\JWT\Signer\Key\LocalFileReference
 * @covers \Lcobucci\JWT\Signer\Key\InMemory
 * @covers \Lcobucci\JWT\Signer\Ecdsa
 * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 */
class ES512TokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    /** @before */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            Sha512::create(),
            static::$ecdsaKeys['private_ec512'],
            static::$ecdsaKeys['public_ec512']
        );
    }

    /** @test */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:');

        $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
            ->getToken($this->config->signer(), InMemory::plainText('testing'));
    }

    /** @test */
    public function builderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('This key is not compatible with this signer');

        $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
            ->getToken($this->config->signer(), static::$rsaKeys['private']);
    }

    /** @test */
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $token = $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->permittedFor('http://client2.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', $user)
            ->withHeader('jki', '1234')
            ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertEquals('1234', $token->headers()->get('jki'));
        self::assertEquals('http://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertEquals($user, $token->claims()->get('user'));

        self::assertEquals(
            ['http://client.abc.com', 'http://client2.abc.com'],
            $token->claims()->get(Token\RegisteredClaims::AUDIENCE)
        );

        return $token;
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function parserCanReadAToken(Token $generated): void
    {
        $read = $this->config->parser()->parse($generated->toString());
        assert($read instanceof Token\Plain);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->claims()->get('user')['name']);
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRight(Token $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                $this->config->signer(),
                self::$ecdsaKeys['public2_ec512']
            )
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function signatureAssertionShouldRaiseExceptionWhenAlgorithmIsDifferent(Token $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                Sha256::create(),
                self::$ecdsaKeys['public_ec512']
            )
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(Token $token): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('This key is not compatible with this signer');

        $this->config->validator()->assert(
            $token,
            new SignedWith($this->config->signer(), self::$rsaKeys['public'])
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith(
            $this->config->signer(),
            $this->config->verificationKey()
        );

        self::assertTrue($this->config->validator()->validate($token, $constraint));
    }
}
