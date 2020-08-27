<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Key */
final class KeyTest extends TestCase
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
     * @covers ::__construct
     * @covers ::setContent
     * @covers ::readFile
     */
    public function constructShouldRaiseExceptionWhenFileDoesNotExists(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('You must provide a valid key file');

        new Key('file://' . vfsStream::url('root/test2.pem'));
    }

    /**
     * @test
     *
     * @covers ::getContent
     *
     * @uses \Lcobucci\JWT\Signer\Key::__construct
     * @uses \Lcobucci\JWT\Signer\Key::setContent
     */
    public function getContentShouldReturnConfiguredData(): void
    {
        $key = new Key('testing', 'test');

        self::assertSame('testing', $key->getContent());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::setContent
     * @covers ::readFile
     * @covers ::getContent
     */
    public function getContentShouldReturnFileContentsWhenFilePathHasBeenPassed(): void
    {
        $key = new Key('file://' . vfsStream::url('root/test.pem'));

        self::assertSame('testing', $key->getContent());
    }

    /**
     * @test
     *
     * @covers ::getPassphrase
     *
     * @uses \Lcobucci\JWT\Signer\Key::__construct
     * @uses \Lcobucci\JWT\Signer\Key::setContent
     */
    public function getPassphraseShouldReturnConfiguredData(): void
    {
        $key = new Key('testing', 'test');

        self::assertSame('test', $key->getPassphrase());
    }

    /**
     * @test
     *
     * @covers ::getPassphrase
     *
     * @uses \Lcobucci\JWT\Signer\Key::__construct
     * @uses \Lcobucci\JWT\Signer\Key::setContent
     */
    public function getPassphraseShouldReturnAnEmptyStringWhenNothingWasConfigured(): void
    {
        $key = new Key('testing');

        self::assertSame('', $key->getPassphrase());
    }
}
