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

use const PHP_EOL;

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
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\InvalidToken
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 */
class EcdsaTokenTest extends TestCase
{
    use Keys;

    private Configuration $config;

    /** @before */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            Sha256::create(),
            static::$ecdsaKeys['private'],
            static::$ecdsaKeys['public1']
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
                self::$ecdsaKeys['public2']
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
                Sha512::create(),
                self::$ecdsaKeys['public1']
            )
        );
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
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
     */
    public function signatureValidationShouldSucceedWhenKeyIsRight(Token $token): void
    {
        $constraint = new SignedWith(
            $this->config->getSigner(),
            $this->config->getVerificationKey()
        );

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
    }

    /** @test */
    public function everythingShouldWorkWithAKeyWithParams(): void
    {
        $builder = $this->config->createBuilder();
        $signer  = $this->config->getSigner();

        $token = $builder->identifiedBy('1')
                         ->permittedFor('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->withClaim('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                         ->withHeader('jki', '1234')
                         ->getToken($signer, static::$ecdsaKeys['private-params']);

        $constraint = new SignedWith(
            $this->config->getSigner(),
            static::$ecdsaKeys['public-params']
        );

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
    }

    /** @test */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs(): void
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
                . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
                . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
                . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        $key = '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
               . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
               . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
               . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
               . '-----END PUBLIC KEY-----';

        $token = $this->config->getParser()->parse($data);
        assert($token instanceof Token\Plain);
        $constraint = new SignedWith(Sha512::create(), new Key($key));

        self::assertTrue($this->config->getValidator()->validate($token, $constraint));
        self::assertEquals('world', $token->claims()->get('hello'));
    }
}
