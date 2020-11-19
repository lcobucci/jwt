<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Key\LocalFileReference */
final class LocalFileReferenceTest extends TestCase
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
     * @covers ::file
     * @covers \Lcobucci\JWT\Signer\Key\FileCouldNotBeRead
     */
    public function thereShouldBeNoReferenceToAFileThatDoesNotExist(): void
    {
        $this->expectException(FileCouldNotBeRead::class);
        $this->expectExceptionMessage('The path "vfs://root/test2.pem" does not contain a valid key file');

        LocalFileReference::file(vfsStream::url('root/test2.pem'));
    }

    /**
     * @test
     *
     * @covers ::file
     * @covers ::__construct
     * @covers ::contents
     * @covers ::passphrase
     */
    public function contentsShouldReturnOnlyTheReferenceToTheFile(): void
    {
        $key = LocalFileReference::file(vfsStream::url('root/test.pem'), 'test');

        self::assertSame('file://vfs://root/test.pem', $key->contents());
        self::assertSame('test', $key->passphrase());
    }
}
