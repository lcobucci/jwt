<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha256K;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\CoversClass(JoseEncoder::class)]
#[PHPUnit\CoversClass(ChainedFormatter::class)]
#[PHPUnit\CoversClass(MicrosecondBasedDateConversion::class)]
#[PHPUnit\CoversClass(UnifyAudience::class)]
#[PHPUnit\CoversClass(Token\Builder::class)]
#[PHPUnit\CoversClass(Token\Parser::class)]
#[PHPUnit\CoversClass(Token\Plain::class)]
#[PHPUnit\CoversClass(Token\DataSet::class)]
#[PHPUnit\CoversClass(Token\Signature::class)]
#[PHPUnit\CoversClass(Ecdsa::class)]
#[PHPUnit\CoversClass(Ecdsa\MultibyteStringConverter::class)]
#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(Sha256K::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
final class ES256KTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Sha256K(),
            static::$ecdsaKeys['private_secp256k1'],
            static::$ecdsaKeys['public_secp256k1'],
        );
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->builder()
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('It was not possible to parse your key, reason:');

        $void = $builder->getToken($this->config->signer(), InMemory::plainText('testing'));
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(): void
    {
        $builder = $this->config->builder()
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "EC", "RSA" provided');

        $void = $builder->getToken($this->config->signer(), static::$rsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyCurveIsNotSecp256k1(): void
    {
        $builder = $this->config->builder()
            ->identifiedBy('1')
            ->permittedFor('https://client.abc.com')
            ->issuedBy('https://api.abc.com')
            ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com']);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "secp256k1", "prime256v1" provided',
        );

        $void = $builder->getToken($this->config->signer(), static::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $token = $builder->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->permittedFor('https://client2.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->withClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame('https://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertSame($user, $token->claims()->get('user'));

        self::assertSame(
            ['https://client.abc.com', 'https://client2.abc.com'],
            $token->claims()->get(Token\RegisteredClaims::AUDIENCE),
        );

        return $token;
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function parserCanReadAToken(Token $generated): void
    {
        $read = $this->config->parser()->parse($generated->toString());
        assert($read instanceof Token\Plain);

        self::assertEquals($generated, $read);
        self::assertSame('testing', $read->claims()->get('user')['name']);
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRight(Token $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessageIsOrContains('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                $this->config->signer(),
                self::$ecdsaKeys['public2_secp256k1'],
            ),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenAlgorithmIsDifferent(Token $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessageIsOrContains('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                new Sha256(),
                self::$ecdsaKeys['public1'],
            ),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(Token $token): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "EC", "RSA" provided');

        $this->config->validator()->assert(
            $token,
            new SignedWith($this->config->signer(), self::$rsaKeys['public']),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenKeyCurveIsNotSecp256k1(Token $token): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'The curve of the provided key is not "secp256k1", "prime256v1" provided',
        );

        $this->config->validator()->assert(
            $token,
            new SignedWith($this->config->signer(), self::$ecdsaKeys['public1']),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith(
            $this->config->signer(),
            $this->config->verificationKey(),
        );

        self::assertTrue($this->config->validator()->validate($token, $constraint));
    }
}
