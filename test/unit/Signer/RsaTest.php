<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\UnsafeSha256;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

use function assert;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const OPENSSL_ALGO_SHA256;
use const PHP_EOL;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Rsa */
final class RsaTest extends TestCase
{
    use Keys;

    /** @after */
    public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers ::guardAgainstIncompatibleKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldReturnAValidOpensslSignature(): void
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$rsaKeys['private']);

        $publicKey = openssl_pkey_get_public(self::$rsaKeys['public']->contents());
        assert($publicKey instanceof OpenSSLAsymmetricKey);

        self::assertSame(1, openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA256));
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\CannotSignPayload
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyIsInvalid(): void
    {
        $key = <<<'KEY'
-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQC4MRKSVsq5XnRBrJoX6+rnAgMBAAECECO8SZkgw6Yg66A6SUly/3kC
CQDtPXZtCQWJuwIJAMbBu17GDOrFAggopfhNlFcjkwIIVjb7G+U0/TECCEERyvxP
TWdN
-----END RSA PRIVATE KEY-----
KEY;

        $signer = new UnsafeSha256();

        $this->expectException(CannotSignPayload::class);
        $this->expectExceptionMessage('There was an error while creating the signature:' . PHP_EOL . '* error:');

        $signer->sign('testing', InMemory::plainText($key));
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:' . PHP_EOL . '* error:');

        $signer->sign('testing', InMemory::plainText('blablabla'));
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function allOpenSSLErrorsShouldBeOnTheErrorMessage(): void
    {
        $signer = $this->getSigner();

        // Injects a random OpenSSL error message
        openssl_pkey_get_private('blahblah');

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageMatches('/^.* reason:(' . PHP_EOL . '\* error:.*){2,}/');

        $signer->sign('testing', InMemory::plainText('blablabla'));
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers ::guardAgainstIncompatibleKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('The type of the provided key is not "RSA", "EC" provided');

        $signer->sign('testing', self::$ecdsaKeys['private']);
    }

    /**
     * @test
     *
     * @covers ::sign
     * @covers ::guardAgainstIncompatibleKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 2048 bits, only 512 bits provided');

        $signer->sign('testing', self::$rsaKeys['private_short']);
    }

    /**
     * @test
     *
     * @covers ::verify
     * @covers ::guardAgainstIncompatibleKey
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue($signer->verify($signature, $payload, self::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @covers ::verify
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key, reason:' . PHP_EOL . '* error:');

        $signer->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    /**
     * @test
     *
     * @covers ::verify
     * @covers \Lcobucci\JWT\Signer\OpenSSL
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $signer = $this->getSigner();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('It was not possible to parse your key');

        $signer->verify('testing', 'testing', self::$ecdsaKeys['private']);
    }

    private function getSigner(): Rsa
    {
        $signer = $this->getMockForAbstractClass(Rsa::class);

        $signer->method('algorithm')
               ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('algorithmId')
               ->willReturn('RS256');

        return $signer;
    }
}
