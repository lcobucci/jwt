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
     */
    public function fromEmptyDataShouldReturnAnEmptySignature(): void
    {
        $signature = Signature::fromEmptyData();

        self::assertAttributeEmpty('hash', $signature);
        self::assertAttributeEmpty('encoded', $signature);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::hash
     */
    public function hashShouldReturnTheHash(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertEquals('test', $signature->hash());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Signature::__construct
     * @covers \Lcobucci\JWT\Token\Signature::__toString
     */
    public function toStringMustReturnTheEncodedData(): void
    {
        $signature = new Signature('test', 'encoded');

        self::assertEquals('encoded', (string) $signature);
    }
}
