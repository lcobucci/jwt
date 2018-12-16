<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use PHPUnit\Framework\TestCase;

final class SignatureTest extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::fromEmptyData
     * @covers \Lcobucci\JWT\Token\Signature::__toString
     * @covers \Lcobucci\JWT\Token\Signature::hash
     */
    public function fromEmptyDataShouldReturnAnEmptySignature(): void
    {
        $signature = Signature::fromEmptyData();

        self::assertSame('', $signature->hash());
        self::assertSame('', (string) $signature);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::hash
     * @covers \Lcobucci\JWT\Token\Signature::__toString
     */
    public function hashShouldReturnTheHash(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertSame('test', $signature->hash());
        self::assertSame('encoded', (string) $signature);
    }
}
