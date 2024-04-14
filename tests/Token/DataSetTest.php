<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use Lcobucci\JWT\Token\DataSet;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(DataSet::class)]
final class DataSetTest extends TestCase
{
    #[PHPUnit\Test]
    public function getShouldReturnTheConfiguredValue(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(1, $set->get('one'));
    }

    #[PHPUnit\Test]
    public function getShouldReturnTheFallbackValueWhenItWasGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame(2, $set->get('two', 2));
    }

    #[PHPUnit\Test]
    public function getShouldReturnNullWhenFallbackValueWasNotGiven(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertNull($set->get('two'));
    }

    #[PHPUnit\Test]
    public function hasShouldReturnTrueWhenItemWasConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertTrue($set->has('one'));
    }

    #[PHPUnit\Test]
    public function hasShouldReturnFalseWhenItemWasNotConfigured(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertFalse($set->has('two'));
    }

    #[PHPUnit\Test]
    public function allShouldReturnAllConfiguredItems(): void
    {
        $items = ['one' => 1, 'two' => 2];
        $set   = new DataSet($items, 'one=1');

        self::assertSame($items, $set->all());
    }

    #[PHPUnit\Test]
    public function toStringShouldReturnTheEncodedData(): void
    {
        $set = new DataSet(['one' => 1], 'one=1');

        self::assertSame('one=1', $set->toString());
    }
}
