<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Signer\Eddsa;
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
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(Eddsa::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
class EddsaTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Eddsa(),
            static::$eddsaKeys['private'],
            static::$eddsaKeys['public1'],
        );
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $builder->identifiedBy('1')
                ->permittedFor('https://client.abc.com')
                ->issuedBy('https://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->signer(), InMemory::plainText('testing'));
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
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                $this->config->signer(),
                self::$eddsaKeys['public2'],
            ),
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
