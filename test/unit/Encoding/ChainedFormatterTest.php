<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Encoding\ChainedFormatter */
final class ChainedFormatterTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::default
     * @covers ::formatClaims
     *
     * @uses \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
     * @uses \Lcobucci\JWT\Encoding\UnifyAudience
     */
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
    }
}
