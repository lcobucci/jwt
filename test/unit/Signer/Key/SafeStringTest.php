<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

use function base64_encode;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Key\SafeString */
final class SafeStringTest extends TestCase
{
    /** @before */
    public function configureRootDir(): void
    {
        vfsStream::setup(
            'root',
            null,
            ['test.pem' => 'testing']
        );
    }

    /**
     * @test
     *
     * @covers ::base64Encoded
     * @covers \Lcobucci\JWT\Encoding\CannotDecodeContent
     */
    public function exceptionShouldBeRaisedWhenInvalidBase64CharsAreUsed(): void
    {
        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

        SafeString::base64Encoded('ááá');
    }

    /**
     * @test
     *
     * @covers ::base64Encoded
     * @covers ::__construct
     * @covers ::contents
     */
    public function base64EncodedShouldDecodeKeyContents(): void
    {
        $key = SafeString::base64Encoded(base64_encode('testing'));

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::empty
     * @covers ::__construct
     * @covers ::contents
     * @covers ::passphrase
     */
    public function emptyShouldCreateAKeyWithEmptyContentsAndPassphrase(): void
    {
        $key = SafeString::empty();

        self::assertSame('', $key->contents());
        self::assertSame('', $key->passphrase());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::file
     * @covers \Lcobucci\JWT\Signer\Key\FileCouldNotBeRead
     */
    public function exceptionShouldBeRaisedWhenFileDoesNotExists(): void
    {
        $path = vfsStream::url('root/test2.pem');

        $this->expectException(FileCouldNotBeRead::class);
        $this->expectExceptionMessage('The path "' . $path . '" does not contain a valid key file');
        $this->expectExceptionCode(0);

        SafeString::file($path);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::plainText
     * @covers ::contents
     */
    public function contentsShouldReturnConfiguredData(): void
    {
        $key = SafeString::plainText('testing', 'test');

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::file
     * @covers ::contents
     */
    public function contentsShouldReturnFileContentsWhenFilePathHasBeenPassed(): void
    {
        $key = SafeString::file(vfsStream::url('root/test.pem'));

        self::assertSame('testing', $key->contents());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::plainText
     * @covers ::passphrase
     */
    public function passphraseShouldReturnConfiguredData(): void
    {
        $key = SafeString::plainText('testing', 'test');

        self::assertSame('test', $key->passphrase());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::plainText
     * @covers ::passphrase
     */
    public function passphraseShouldReturnAnEmptyStringWhenNothingWasConfigured(): void
    {
        $key = SafeString::plainText('testing');

        self::assertSame('', $key->passphrase());
    }
}
