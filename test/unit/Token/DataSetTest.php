<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Token\DataSet */
final class DataSetTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnTheConfiguredValue(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(1, $set->get('one'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnTheFallbackValueWhenItWasGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(2, $set->get('two', 2));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnNullWhenFallbackValueWasNotGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertNull($set->get('two'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::has
     */
    public function hasShouldReturnTrueWhenItemWasConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertTrue($set->has('one'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::has
     */
    public function hasShouldReturnFalseWhenItemWasNotConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertFalse($set->has('two'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::all
     */
    public function allShouldReturnAllConfiguredItems(): void
    {
        $items = ['one' => 1, 'two' => 2];
        $set   = new DataSet($items, 'one=1');

        self::assertSame($items, $set->all());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::toString
     */
    public function toStringShouldReturnTheEncodedData(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame('one=1', $set->toString());
    }
}
