<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Encoding\UnixTimestampDates;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(ChainedFormatter::class)]
#[PHPUnit\UsesClass(MicrosecondBasedDateConversion::class)]
#[PHPUnit\UsesClass(UnifyAudience::class)]
#[PHPUnit\UsesClass(UnixTimestampDates::class)]
final class ChainedFormatterTest extends TestCase
{
    #[PHPUnit\Test]
    public function formatClaimsShouldApplyAllConfiguredFormatters(): void
    {
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');
        self::assertInstanceOf(DateTimeImmutable::class, $expiration);

        $claims = [
            RegisteredClaims::AUDIENCE        => ['test'],
            RegisteredClaims::EXPIRATION_TIME => $expiration,
        ];

        $formatter = ChainedFormatter::default();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame('test', $formatted[RegisteredClaims::AUDIENCE]);
        self::assertSame(1487285080.123456, $formatted[RegisteredClaims::EXPIRATION_TIME]);

        $formatter = ChainedFormatter::withUnixTimestampDates();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame('test', $formatted[RegisteredClaims::AUDIENCE]);
        self::assertSame(1487285080, $formatted[RegisteredClaims::EXPIRATION_TIME]);
    }
}
