<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Rsa\Sha512;
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
#[PHPUnit\CoversClass(Encoding\JoseEncoder::class)]
#[PHPUnit\CoversClass(Encoding\ChainedFormatter::class)]
#[PHPUnit\CoversClass(Encoding\MicrosecondBasedDateConversion::class)]
#[PHPUnit\CoversClass(Encoding\UnifyAudience::class)]
#[PHPUnit\CoversClass(Token\Builder::class)]
#[PHPUnit\CoversClass(Token\Parser::class)]
#[PHPUnit\CoversClass(Token\Plain::class)]
#[PHPUnit\CoversClass(Token\DataSet::class)]
#[PHPUnit\CoversClass(Token\Signature::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(Rsa::class)]
#[PHPUnit\CoversClass(Rsa\Sha256::class)]
#[PHPUnit\CoversClass(Rsa\Sha512::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
class RsaTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new Sha256(),
            static::$rsaKeys['private'],
            static::$rsaKeys['public'],
        );
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyIsInvalid(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $builder->identifiedBy('1')
                ->permittedFor('https://client.abc.com')
                ->issuedBy('https://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->signer(), InMemory::plainText('testing'));
    }

    #[PHPUnit\Test]
    public function builderShouldRaiseExceptionWhenKeyIsNotRsaCompatible(): void
    {
        $builder = $this->config->builder();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $builder->identifiedBy('1')
                ->permittedFor('https://client.abc.com')
                ->issuedBy('https://api.abc.com')
                ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->getToken($this->config->signer(), static::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $token = $builder->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->withClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertSame('1234', $token->headers()->get('jki'));
        self::assertSame(['https://client.abc.com'], $token->claims()->get(Token\RegisteredClaims::AUDIENCE));
        self::assertSame('https://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertSame($user, $token->claims()->get('user'));

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
            new SignedWith($this->config->signer(), self::$rsaKeys['encrypted-public']),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenAlgorithmIsDifferent(Token $token): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert(
            $token,
            new SignedWith(new Sha512(), $this->config->verificationKey()),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureAssertionShouldRaiseExceptionWhenKeyIsNotRsaCompatible(Token $token): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $this->config->validator()->assert(
            $token,
            new SignedWith(
                $this->config->signer(),
                self::$ecdsaKeys['public1'],
            ),
        );
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        self::assertTrue($this->config->validator()->validate($token, $constraint));
    }

    #[PHPUnit\Test]
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $data = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.s'
                . 'GYbB1KrmnESNfJ4D9hOe1Zad_BMyxdb8G4p4LNP7StYlOyBWck6q7XPpPj_6gB'
                . 'Bo1ohD3MA2o0HY42lNIrAStaVhfsFKGdIou8TarwMGZBPcif_3ThUV1pGS3fZc'
                . 'lFwF2SP7rqCngQis_xcUVCyqa8E1Wa_v28grnl1QZrnmQFO8B5JGGLqcrfUHJO'
                . 'nJCupP-Lqh4TmIhftIimSCgLNmJg80wyrpUEfZYReE7hPuEmY0ClTqAGIMQoNS'
                . '98ljwDxwhfbSuL2tAdbV4DekbTpWzspe3dOJ7RSzmPKVZ6NoezaIazKqyqkmHZfcMaHI1lQeGia6LTbHU1bp0gINi74Vw';

        $token = $this->config->parser()->parse($data);
        assert($token instanceof Token\Plain);
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        self::assertTrue($this->config->validator()->validate($token, $constraint));
        self::assertSame('world', $token->claims()->get('hello'));
    }
}
