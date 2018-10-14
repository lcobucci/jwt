<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use org\bovigo\vfs\vfsStream;
use PHPUnit\Framework\TestCase;

final class KeyTest extends TestCase
{
    /**
     * @before
     */
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
     * @covers \Lcobucci\JWT\Signer\Key::__construct
     * @covers \Lcobucci\JWT\Signer\Key::setContent
     */
    public function constructShouldConfigureContentAndPassphrase(): void
    {
        $key = new Key('testing', 'test');

        self::assertAttributeEquals('testing', 'content', $key);
        self::assertAttributeEquals('test', 'passphrase', $key);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Key::__construct
     * @covers \Lcobucci\JWT\Signer\Key::setContent
     * @covers \Lcobucci\JWT\Signer\Key::readFile
     */
    public function constructShouldBeAbleToConfigureContentFromFile(): void
    {
        $key = new Key('file://' . vfsStream::url('root/test.pem'));

        self::assertAttributeEquals('testing', 'content', $key);
        self::assertAttributeEquals(null, 'passphrase', $key);
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Key::__construct
     * @covers \Lcobucci\JWT\Signer\Key::setContent
     * @covers \Lcobucci\JWT\Signer\Key::readFile
     */
    public function constructShouldRaiseExceptionWhenFileDoesNotExists(): void
    {
        new Key('file://' . vfsStream::url('root/test2.pem'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Key::getContent
     *
     * @uses \Lcobucci\JWT\Signer\Key::__construct
     * @uses \Lcobucci\JWT\Signer\Key::setContent
     */
    public function getContentShouldReturnConfiguredData(): void
    {
        $key = new Key('testing', 'test');

        self::assertEquals('testing', $key->getContent());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Key::getPassphrase
     *
     * @uses \Lcobucci\JWT\Signer\Key::__construct
     * @uses \Lcobucci\JWT\Signer\Key::setContent
     */
    public function getPassphraseShouldReturnConfiguredData(): void
    {
        $key = new Key('testing', 'test');

        self::assertEquals('test', $key->getPassphrase());
    }
}
