<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use InvalidArgumentException;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\InvalidToken;
use PHPUnit\Framework\TestCase;

use function assert;

/**
 * @covers \Lcobucci\JWT\Configuration
 * @covers \Lcobucci\JWT\Encoding\JoseEncoder
 * @covers \Lcobucci\JWT\Token\Builder
 * @covers \Lcobucci\JWT\Token\Parser
 * @covers \Lcobucci\JWT\Token\Plain
 * @covers \Lcobucci\JWT\Token\DataSet
 * @covers \Lcobucci\JWT\Token\Signature
 * @covers \Lcobucci\JWT\Signer\Key
 * @covers \Lcobucci\JWT\Signer\Ecdsa
 * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\InvalidToken
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
        $builder = $this->config->createBuilder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:');

        $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
            ->getToken($this->config->getSigner(), new Key('testing'));
    }

    /** @test */
    public function builderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(): void
    {
        $builder = $this->config->createBuilder();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key is not compatible with this signer');

        $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
            ->getToken($this->config->getSigner(), static::$rsaKeys['private']);
    }

    /** @test */
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->identifiedBy('1')
            ->permittedFor('http://client.abc.com')
            ->permittedFor('http://client2.abc.com')
            ->issuedBy('http://api.abc.com')
            ->withClaim('user', $user)
            ->withHeader('jki', '1234')
            ->getToken($this->config->getSigner(), $this->config->getSigningKey());

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
        $read = $this->config->getParser()->parse($generated->toString());
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
        $this->expectException(InvalidToken::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->getValidator()->assert(
            $token,
            new SignedWith(
                $this->config->getSigner(),
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
        $this->expectException(InvalidToken::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->getValidator()->assert(
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
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\InvalidToken
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(Token $token): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('This key is not compatible with this signer');

        $this->config->getValidator()->assert(
            $token,
            new SignedWith($this->config->getSigner(), self::$rsaKeys['public'])
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Validation\Validator
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith(
            $this->config->getSigner(),
            $this->config->getVerificationKey()
        );

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
    }
}
