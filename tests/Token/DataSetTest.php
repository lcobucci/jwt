<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use Lcobucci\JWT\Token\DataSet;
use PHPUnit\Framework\TestCase;

/** @covers \Lcobucci\JWT\Token\DataSet */
final class DataSetTest extends TestCase
{
    /** @test */
    public function getShouldReturnTheConfiguredValue(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(1, $set->get('one'));
    }

    /** @test */
    public function getShouldReturnTheFallbackValueWhenItWasGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(2, $set->get('two', 2));
    }

    /** @test */
    public function getShouldReturnNullWhenFallbackValueWasNotGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertNull($set->get('two'));
    }

    /** @test */
    public function hasShouldReturnTrueWhenItemWasConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertTrue($set->has('one'));
    }

    /** @test */
    public function hasShouldReturnFalseWhenItemWasNotConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertFalse($set->has('two'));
    }

    /** @test */
    public function allShouldReturnAllConfiguredItems(): void
    {
        $items = ['one' => 1, 'two' => 2];
        $set   = new DataSet($items, 'one=1');

        self::assertSame($items, $set->all());
    }

    /** @test */
    public function toStringShouldReturnTheEncodedData(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame('one=1', $set->toString());
    }
}
