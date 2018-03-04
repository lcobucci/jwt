<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use PHPUnit\Framework\TestCase;

final class DataSetTest extends TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnTheConfiguredValue(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertEquals(1, $set->get('one'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnTheFallbackValueWhenItWasGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertEquals(2, $set->get('two', 2));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::get
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
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::has
     */
    public function hasShouldReturnTrueWhenItemWasConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertTrue($set->has('one'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::has
     */
    public function hasShouldReturnFalseWhenItemWasNotConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertFalse($set->has('two'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::all
     */
    public function allShouldReturnAllConfiguredItems(): void
    {
        $items = ['one' => 1, 'two' => 2];
        $set   = new DataSet($items, 'one=1');

        self::assertEquals($items, $set->all());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::__toString
     */
    public function toStringShouldReturnTheEncodedData(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertEquals('one=1', (string) $set);
    }
}
