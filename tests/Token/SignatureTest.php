<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\TestCase;

/**
 * @covers ::__construct
 * @covers ::toString
 * @covers ::hash
 * @coversDefaultClass \Lcobucci\JWT\Token\Signature
 */
final class SignatureTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::fromEmptyData
     */
    public function fromEmptyDataShouldReturnAnEmptySignature(): void
    {
        $signature = Signature::fromEmptyData();

        self::assertSame('', $signature->hash());
        self::assertSame('', $signature->toString());
    }

    /** @test */
    public function hashShouldReturnTheHash(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertSame('test', $signature->hash());
        self::assertSame('encoded', $signature->toString());
    }
}
