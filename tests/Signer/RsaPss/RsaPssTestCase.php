<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Tests\Keys;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;
use function chr;
use function explode;
use function hash;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_public_decrypt;
use function openssl_sign;
use function openssl_verify;
use function ord;
use function pack;
use function sodium_base642bin;
use function strlen;
use function strpos;
use function substr;

use const OPENSSL_NO_PADDING;
use const OPENSSL_PKCS1_PSS_PADDING;
use const PHP_EOL;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

abstract class RsaPssTestCase extends TestCase
{
    use Keys;

    abstract protected function algorithm(): RsaPss;

    abstract protected function algorithmId(): string;

    abstract protected function signatureAlgorithm(): int;

    /** @return non-empty-string */
    abstract protected function hashAlgorithm(): string;

    /**
     * Token signed with `tests/_keys/rsa/private.key` by another library
     *
     * @return non-empty-string
     */
    abstract protected function tokenGeneratedByOtherLibs(): string;

    #[PHPUnit\After]
    final public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    #[PHPUnit\Test]
    final public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame($this->algorithmId(), $this->algorithm()->algorithmId());
    }

    #[PHPUnit\Test]
    final public function signatureAlgorithmMustBeCorrect(): void
    {
        self::assertSame($this->signatureAlgorithm(), $this->algorithm()->algorithm());
    }

    #[PHPUnit\Test]
    public function signShouldReturnAValidOpensslPssSignature(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private']);

        self::assertSame(
            1,
            openssl_verify(
                $payload,
                $signature,
                $this->publicKey(),
                $this->signatureAlgorithm(),
                OPENSSL_PKCS1_PSS_PADDING,
            ),
        );
    }

    #[PHPUnit\Test]
    public function signShouldNotReturnAPkcs1Signature(): void
    {
        $payload   = 'testing';
        $signature = $this->algorithm()->sign($payload, self::$rsaKeys['private']);

        self::assertSame(0, openssl_verify($payload, $signature, $this->publicKey(), $this->signatureAlgorithm()));
    }

    /** @see https://www.rfc-editor.org/rfc/rfc7518#section-3.5 */
    #[PHPUnit\Test]
    public function signShouldUseASaltAsLongAsTheHashOutput(): void
    {
        $signature = $this->algorithm()->sign('testing', self::$rsaKeys['private']);

        self::assertSame(strlen(hash($this->hashAlgorithm(), '', true)), $this->saltLength($signature));
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'It was not possible to parse your key, reason:' . PHP_EOL . '* error:',
        );

        $this->algorithm()->sign('testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "RSA", "EC" provided');

        $this->algorithm()->sign('testing', self::$ecdsaKeys['private']);
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsRestrictedToPss(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "RSA", "unknown" provided');

        $this->algorithm()->sign('testing', self::$rsaKeys['private_pss']);
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyLengthIsBelowMinimum(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('Key provided is shorter than 2048 bits, only 512 bits provided');

        $this->algorithm()->sign('testing', self::$rsaKeys['private_short']);
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, $this->signatureAlgorithm(), OPENSSL_PKCS1_PSS_PADDING);

        self::assertTrue($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public']));
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnFalseWhenSignatureUsesPkcs1Padding(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_pkey_get_private(self::$rsaKeys['private']->contents());
        assert($privateKey instanceof OpenSSLAsymmetricKey);

        $signature = '';
        openssl_sign($payload, $signature, $privateKey, $this->signatureAlgorithm());

        self::assertFalse($this->algorithm()->verify($signature, $payload, self::$rsaKeys['public']));
    }

    #[PHPUnit\Test]
    public function verifyShouldAcceptSignaturesCreatedByOtherLibs(): void
    {
        [$header, $claims, $encodedSignature] = explode('.', $this->tokenGeneratedByOtherLibs());

        $signature = sodium_base642bin($encodedSignature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        assert($signature !== '');

        self::assertTrue(
            $this->algorithm()->verify(
                $signature,
                $header . '.' . $claims,
                self::$rsaKeys['public'],
            ),
        );
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains(
            'It was not possible to parse your key, reason:' . PHP_EOL . '* error:',
        );

        $this->algorithm()->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "RSA", "EC" provided');

        $this->algorithm()->verify('testing', 'testing', self::$ecdsaKeys['public1']);
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyIsRestrictedToPss(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessageIsOrContains('The type of the provided key is not "RSA", "unknown" provided');

        $this->algorithm()->verify('testing', 'testing', self::$rsaKeys['public_pss']);
    }

    private function publicKey(): OpenSSLAsymmetricKey
    {
        $publicKey = openssl_pkey_get_public(self::$rsaKeys['public']->contents());
        assert($publicKey instanceof OpenSSLAsymmetricKey);

        return $publicKey;
    }

    /**
     * Recovers the salt length from an EMSA-PSS encoded signature
     *
     * @see https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2
     */
    private function saltLength(string $signature): int
    {
        $encoded = '';
        openssl_public_decrypt($signature, $encoded, $this->publicKey(), OPENSSL_NO_PADDING);
        assert(is_string($encoded));

        $hashLength = strlen(hash($this->hashAlgorithm(), '', true));
        $maskedDb   = substr($encoded, 0, -$hashLength - 1);
        $hash       = substr($encoded, -$hashLength - 1, $hashLength);

        $mask = '';

        for ($counter = 0; strlen($mask) < strlen($maskedDb); ++$counter) {
            $mask .= hash($this->hashAlgorithm(), $hash . pack('N', $counter), true);
        }

        $db    = $maskedDb ^ substr($mask, 0, strlen($maskedDb));
        $db[0] = chr(ord($db[0]) & 0x7f);

        $separator = strpos($db, "\x01");
        assert($separator !== false);

        return strlen($db) - $separator - 1;
    }
}
