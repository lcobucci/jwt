<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Eddsa;
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
 * @covers \Lcobucci\JWT\Signer\Eddsa
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 */
class EddsaTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    /** @before */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Eddsa(),
            static::$eddsaKeys['private'],
            static::$eddsaKeys['public1']
        );
    }

    /** @test */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $builder->identifiedBy('1')
                ->permittedFor('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->signer(), InMemory::plainText('testing'));
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
                self::$eddsaKeys['public2']
            )
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
