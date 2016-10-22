<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Token;

final class DataSetTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::get
     *
     * @uses \Lcobucci\JWT\Token\DataSet::has
     */
    public function getShouldReturnTheConfiguredValue()
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
    public function getShouldReturnTheFallbackValueWhenItWasGiven()
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
    public function getShouldReturnNullWhenFallbackValueWasNotGiven()
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
    public function hasShouldReturnTrueWhenItemWasConfigured()
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
    public function hasShouldReturnFalseWhenItemWasNotConfigured()
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
    public function allShouldReturnAllConfiguredItems()
    {
        $items = ['one' => 1, 'two' => 2];
        $set = new DataSet($items, 'one=1');

        self::assertEquals($items, $set->all());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\DataSet::__construct
     * @covers \Lcobucci\JWT\Token\DataSet::__toString
     */
    public function toStringShouldReturnTheEncodedData()
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertEquals('one=1', (string) $set);
    }
}
