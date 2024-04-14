<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Key;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\FileCouldNotBeRead;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function base64_encode;

#[PHPUnit\CoversClass(CannotDecodeContent::class)]
#[PHPUnit\CoversClass(FileCouldNotBeRead::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
final class InMemoryTest extends TestCase
{
    #[PHPUnit\Test]
    public function exceptionShouldBeRaisedWhenInvalidBase64CharsAreUsed(): void
    {
        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

        InMemory::base64Encoded('ááá');
    }

    #[PHPUnit\Test]
    public function base64EncodedShouldDecodeKeyContents(): void
    {
        $key = InMemory::base64Encoded(base64_encode('testing'));

        self::assertSame('testing', $key->contents());
    }

    #[PHPUnit\Test]
    public function exceptionShouldBeRaisedWhenFileDoesNotExists(): void
    {
        $path = __DIR__ . '/not-found.pem';

        $this->expectException(FileCouldNotBeRead::class);
        $this->expectExceptionMessage('The path "' . $path . '" does not contain a valid key file');
        $this->expectExceptionCode(0);

        InMemory::file($path);
    }

    #[PHPUnit\Test]
    public function exceptionShouldBeRaisedWhenFileIsEmpty(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key cannot be empty');

        InMemory::file(__DIR__ . '/empty.pem');
    }

    #[PHPUnit\Test]
    public function contentsShouldReturnConfiguredData(): void
    {
        $key = InMemory::plainText('testing', 'test');

        self::assertSame('testing', $key->contents());
    }

    #[PHPUnit\Test]
    public function contentsShouldReturnFileContentsWhenFilePathHasBeenPassed(): void
    {
        $key = InMemory::file(__DIR__ . '/test.pem');

        self::assertSame('testing', $key->contents());
    }

    #[PHPUnit\Test]
    public function passphraseShouldReturnConfiguredData(): void
    {
        $key = InMemory::plainText('testing', 'test');

        self::assertSame('test', $key->passphrase());
    }

    #[PHPUnit\Test]
    public function emptyPlainTextContentShouldRaiseException(): void
    {
        $this->expectException(InvalidKeyProvided::class);

        // @phpstan-ignore-next-line
        InMemory::plainText('');
    }

    #[PHPUnit\Test]
    public function emptyBase64ContentShouldRaiseException(): void
    {
        $this->expectException(InvalidKeyProvided::class);

        // @phpstan-ignore-next-line
        InMemory::base64Encoded('');
    }
}
