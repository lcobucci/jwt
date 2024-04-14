<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\SodiumBase64Polyfill;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function rtrim;
use function sodium_base642bin;

use const SODIUM_BASE64_VARIANT_ORIGINAL;
use const SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING;
use const SODIUM_BASE64_VARIANT_URLSAFE;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\UsesClass(CannotDecodeContent::class)]
final class SodiumBase64PolyfillTest extends TestCase
{
    private const B64    = 'I+o2tVq8ynY=';
    private const B64URL = 'lZ-2HIl9dTz_Oy0nAb-2gvKdG0jhHJ36XB2rWAKj8Uo=';

    #[PHPUnit\Test]
    #[PHPUnit\CoversNothing]
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

    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('base64Variants')]
    public function bin2base64(string $encoded, string $binary, int $variant): void
    {
        self::assertSame($encoded, SodiumBase64Polyfill::bin2base64($binary, $variant));
        self::assertSame($encoded, SodiumBase64Polyfill::bin2base64Fallback($binary, $variant));
    }

    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('base64Variants')]
    public function base642binFallback(string $encoded, string $binary, int $variant): void
    {
        self::assertSame($binary, SodiumBase64Polyfill::base642bin($encoded, $variant));
        self::assertSame($binary, SodiumBase64Polyfill::base642binFallback($encoded, $variant));
    }

    /** @return iterable<array{string, string, int}> */
    public static function base64Variants(): iterable
    {
        $binary = sodium_base642bin(self::B64, SODIUM_BASE64_VARIANT_ORIGINAL, '');

        yield [self::B64, $binary, SODIUM_BASE64_VARIANT_ORIGINAL];
        yield [rtrim(self::B64, '='), $binary, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING];

        $urlBinary = sodium_base642bin(self::B64URL, SODIUM_BASE64_VARIANT_URLSAFE, '');

        yield [self::B64URL, $urlBinary, SODIUM_BASE64_VARIANT_URLSAFE];
        yield [rtrim(self::B64URL, '='), $urlBinary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING];
    }

    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('invalidBase64')]
    public function sodiumBase642BinRaisesExceptionOnInvalidBase64(string $content, int $variant): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642bin($content, $variant);
    }

    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('invalidBase64')]
    public function fallbackBase642BinRaisesExceptionOnInvalidBase64(string $content, int $variant): void
    {
        $this->expectException(CannotDecodeContent::class);

        SodiumBase64Polyfill::base642binFallback($content, $variant);
    }

    /** @return iterable<string, array{string, int}> */
    public static function invalidBase64(): iterable
    {
        yield 'UTF-8 content' => ['ááá', SODIUM_BASE64_VARIANT_ORIGINAL];

        yield 'b64Url variant against original (padded)' => [
            self::B64URL,
            SODIUM_BASE64_VARIANT_ORIGINAL,
        ];

        yield 'b64Url variant against original (not padded)' => [
            rtrim(self::B64URL, '='),
            SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING,
        ];
    }
}
