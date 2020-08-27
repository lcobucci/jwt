<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Token\Signature */
final class SignatureTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::fromEmptyData
     * @covers ::toString
     * @covers ::hash
     */
    public function fromEmptyDataShouldReturnAnEmptySignature(): void
    {
        $signature = Signature::fromEmptyData();

        self::assertSame('', $signature->hash());
        self::assertSame('', $signature->toString());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::hash
     * @covers ::toString
     */
    public function hashShouldReturnTheHash(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertSame('test', $signature->hash());
        self::assertSame('encoded', $signature->toString());
    }
}
