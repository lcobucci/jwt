<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha512;
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
use function file_put_contents;
use function sys_get_temp_dir;
use function tempnam;

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
#[PHPUnit\CoversClass(Hmac::class)]
#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(Sha512::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
class HmacTokenTest extends TestCase
{
    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded('Z0Y6xrhjGQYrEDsP+7aQ3ZAKKERSBeQjP33M0H7Nq6s='),
        );
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
            new SignedWith(
                $this->config->signer(),
                InMemory::base64Encoded('O0MpjL80kE382RyX0rfr9PrNfVclXcdnru2aryanR2o='),
            ),
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
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        self::assertTrue($this->config->validator()->validate($token, $constraint));
    }

    #[PHPUnit\Test]
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $config = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::base64Encoded('FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M='),
        );

        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
              . 'ZQfnc_iFebE--gXmnhJrqMXv3GWdH9uvdkFXTgBcMFw';

        $token = $config->parser()->parse($data);
        assert($token instanceof Token\Plain);
        $constraint = new SignedWith($config->signer(), $config->verificationKey());

        self::assertTrue($config->validator()->validate($token, $constraint));
        self::assertSame('world', $token->claims()->get('hello'));
    }

    #[PHPUnit\Test]
    public function signatureValidationWithLocalFileKeyReferenceWillOperateWithKeyContents(): void
    {
        $key = tempnam(sys_get_temp_dir(), 'a-very-long-prefix-to-create-a-longer-key');
        self::assertIsString($key);

        file_put_contents(
            $key,
            SodiumBase64Polyfill::base642bin(
                'FkL2+V+1k2auI3xxTz/2skChDQVVjT9PW1/grXafg3M=',
                SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
            ),
        );

        $validKey      = InMemory::file($key);
        $invalidKey    = InMemory::plainText('file://' . $key);
        $signer        = new Sha256();
        $configuration = Configuration::forSymmetricSigner($signer, $validKey);
        $validator     = $configuration->validator();

        $token = $configuration->builder()
            ->withClaim('foo', 'bar')
            ->getToken($configuration->signer(), $configuration->signingKey());

        self::assertFalse(
            $validator->validate(
                $token,
                new SignedWith($signer, $invalidKey),
            ),
            'Token cannot be validated against the **path** of the key',
        );

        self::assertTrue(
            $validator->validate(
                $token,
                new SignedWith($signer, $validKey),
            ),
            'Token can be validated against the **contents** of the key',
        );
    }
}
