<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Key;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\FileCouldNotBeRead;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;

use function base64_encode;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Key\InMemory */
final class InMemoryTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::base64Encoded
     * @covers \Lcobucci\JWT\Encoding\CannotDecodeContent
     *
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::base642bin()
     */
    public function exceptionShouldBeRaisedWhenInvalidBase64CharsAreUsed(): void
    {
        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

        InMemory::base64Encoded('ááá');
    }

    /**
     * @test
     *
     * @covers ::base64Encoded
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::contents
     *
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::base642bin()
     */
    public function base64EncodedShouldDecodeKeyContents(): void
    {
        $key = InMemory::base64Encoded(base64_encode('testing'));

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::file
     * @covers \Lcobucci\JWT\Signer\Key\FileCouldNotBeRead
     */
    public function exceptionShouldBeRaisedWhenFileDoesNotExists(): void
    {
        $path = __DIR__ . '/not-found.pem';

        $this->expectException(FileCouldNotBeRead::class);
        $this->expectExceptionMessage('The path "' . $path . '" does not contain a valid key file');
        $this->expectExceptionCode(0);

        InMemory::file($path);
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::file
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided::cannotBeEmpty
     */
    public function exceptionShouldBeRaisedWhenFileIsEmpty(): void
    {
        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key cannot be empty');

        InMemory::file(__DIR__ . '/empty.pem');
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::plainText
     * @covers ::contents
     */
    public function contentsShouldReturnConfiguredData(): void
    {
        $key = InMemory::plainText('testing', 'test');

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::file
     * @covers ::contents
     */
    public function contentsShouldReturnFileContentsWhenFilePathHasBeenPassed(): void
    {
        $key = InMemory::file(__DIR__ . '/test.pem');

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::plainText
     * @covers ::passphrase
     */
    public function passphraseShouldReturnConfiguredData(): void
    {
        $key = InMemory::plainText('testing', 'test');

        self::assertSame('test', $key->passphrase());
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::plainText
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided::cannotBeEmpty
     */
    public function emptyPlainTextContentShouldRaiseException(): void
    {
        $this->expectException(InvalidKeyProvided::class);

        // @phpstan-ignore-next-line
        InMemory::plainText('');
    }

    /**
     * @test
     *
     * @covers ::guardAgainstEmptyKey
     * @covers ::__construct
     * @covers ::base64Encoded
     * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided::cannotBeEmpty
     *
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::base642bin
     */
    public function emptyBase64ContentShouldRaiseException(): void
    {
        $this->expectException(InvalidKeyProvided::class);

        // @phpstan-ignore-next-line
        InMemory::base64Encoded('');
    }
}
