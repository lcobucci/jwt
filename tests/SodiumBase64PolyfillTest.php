<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\SodiumBase64Polyfill;
use PHPUnit\Framework\TestCase;

use function sodium_base642bin;
use function sodium_bin2base64;

use const SODIUM_BASE64_VARIANT_ORIGINAL;
use const SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING;
use const SODIUM_BASE64_VARIANT_URLSAFE;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

/** @coversDefaultClass \Lcobucci\JWT\SodiumBase64Polyfill */
final class SodiumBase64PolyfillTest extends TestCase
{
    private string $testString;

    protected function setUp(): void
    {
        // For proper testing we need a string that can challenge every variant
        $this->testString = sodium_base642bin('I+o2tVq8ynY=', SODIUM_BASE64_VARIANT_ORIGINAL, '');
    }

    /**
     * @test
     *
     * @coversNothing
     */
    public function constantsMatchExtensionOnes(): void
    {
        // @phpstan-ignore-next-line
        self::assertSame(
            SODIUM_BASE64_VARIANT_ORIGINAL,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
        );
        // @phpstan-ignore-next-line
        self::assertSame(
            SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
        );
        // @phpstan-ignore-next-line
        self::assertSame(
            SODIUM_BASE64_VARIANT_URLSAFE,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE,
        );
        // @phpstan-ignore-next-line
        self::assertSame(
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
    }

    /**
     * @test
     * @dataProvider provideVariants
     *
     * @covers ::bin2base64
     * @covers ::bin2base64Fallback
     */
    public function bin2base64(int $variant): void
    {
        $expected = sodium_bin2base64($this->testString, $variant);

        self::assertSame(
            $expected,
            SodiumBase64Polyfill::bin2base64($this->testString, $variant),
        );

        self::assertSame(
            $expected,
            SodiumBase64Polyfill::bin2base64Fallback($this->testString, $variant),
        );
    }

    /**
     * @test
     * @dataProvider provideVariants
     *
     * @covers ::base642bin
     * @covers ::base642binFallback
     */
    public function base642binFallback(int $variant): void
    {
        self::assertSame(
            $this->testString,
            SodiumBase64Polyfill::base642bin(
                sodium_bin2base64($this->testString, $variant),
                $variant,
            ),
        );

        self::assertSame(
            $this->testString,
            SodiumBase64Polyfill::base642binFallback(
                sodium_bin2base64($this->testString, $variant),
                $variant,
            ),
        );
    }

    /** @return int[][] */
    public static function provideVariants(): array
    {
        return [
            [SODIUM_BASE64_VARIANT_ORIGINAL],
            [SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING],
            [SODIUM_BASE64_VARIANT_URLSAFE],
            [SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING],
        ];
    }

    /**
     * @test
     *
     * @covers ::base642bin
     *
     * @uses \Lcobucci\JWT\Encoding\CannotDecodeContent::invalidBase64String()
     */
    public function sodiumBase642BinRaisesExceptionOnInvalidBase64(): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642bin('ááá', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * @test
     *
     * @covers ::base642binFallback
     *
     * @uses \Lcobucci\JWT\Encoding\CannotDecodeContent::invalidBase64String()
     */
    public function fallbackBase642BinRaisesExceptionOnInvalidBase64(): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642binFallback('ááá', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
