<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;

use function assert;
use function file_put_contents;
use function is_string;
use function sys_get_temp_dir;
use function tempnam;

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
 * @covers \Lcobucci\JWT\Signer\Key\InMemory
 * @covers \Lcobucci\JWT\Signer\Hmac
 * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
 * @covers \Lcobucci\JWT\Signer\Hmac\Sha512
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 */
class HmacTokenTest extends TestCase
{
    private Configuration $config;

    /** @before */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText('testing'));
    }

    /** @test */
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $token = $builder->identifiedBy('1')
                         ->permittedFor('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->withClaim('user', $user)
                         ->withHeader('jki', '1234')
                         ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertEquals('1234', $token->headers()->get('jki'));
        self::assertEquals(['http://client.abc.com'], $token->claims()->get(Token\RegisteredClaims::AUDIENCE));
        self::assertEquals('http://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertEquals($user, $token->claims()->get('user'));

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
            new SignedWith($this->config->signer(), InMemory::plainText('testing1'))
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
            new SignedWith(new Sha512(), $this->config->verificationKey())
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        self::assertTrue($this->config->validator()->validate($token, $constraint));
    }

    /** @test */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = $this->config->parser()->parse($data);
        assert($token instanceof Token\Plain);
        $constraint = new SignedWith($this->config->signer(), $this->config->verificationKey());

        self::assertTrue($this->config->validator()->validate($token, $constraint));
        self::assertEquals('world', $token->claims()->get('hello'));
    }

    /** @test */
    public function signatureValidationWithLocalFileKeyReferenceWillOperateWithKeyContents(): void
    {
        $key = tempnam(sys_get_temp_dir(), 'key');
        assert(is_string($key));

        file_put_contents($key, 'just a dummy key');

        $validKey      = LocalFileReference::file($key);
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
                new SignedWith($signer, $invalidKey)
            ),
            'Token cannot be validated against the **path** of the key'
        );

        self::assertTrue(
            $validator->validate(
                $token,
                new SignedWith($signer, $validKey)
            ),
            'Token can be validated against the **contents** of the key'
        );
    }
}
