<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion */
final class MicrosecondBasedDateConversionTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::formatClaims
     * @covers ::convertDate
     */
    public function dateClaimsHaveMicrosecondsOrSeconds(): void
    {
        $issuedAt   = new DateTimeImmutable('@1487285080');
        $notBefore  = DateTimeImmutable::createFromFormat('U.u', '1487285080.000123');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');

        self::assertInstanceOf(DateTimeImmutable::class, $notBefore);
        self::assertInstanceOf(DateTimeImmutable::class, $expiration);

        $claims = [
            RegisteredClaims::ISSUED_AT => $issuedAt,
            RegisteredClaims::NOT_BEFORE => $notBefore,
            RegisteredClaims::EXPIRATION_TIME => $expiration,
            'testing' => 'test',
        ];

        $formatter = new MicrosecondBasedDateConversion();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame(1487285080, $formatted[RegisteredClaims::ISSUED_AT]);
        self::assertSame(1487285080.000123, $formatted[RegisteredClaims::NOT_BEFORE]);
        self::assertSame(1487285080.123456, $formatted[RegisteredClaims::EXPIRATION_TIME]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }

    /**
     * @test
     *
     * @covers ::formatClaims
     * @covers ::convertDate
     */
    public function notAllDateClaimsNeedToBeConfigured(): void
    {
        $issuedAt   = new DateTimeImmutable('@1487285080');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');

        $claims = [
            RegisteredClaims::ISSUED_AT => $issuedAt,
            RegisteredClaims::EXPIRATION_TIME => $expiration,
            'testing' => 'test',
        ];

        $formatter = new MicrosecondBasedDateConversion();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame(1487285080, $formatted[RegisteredClaims::ISSUED_AT]);
        self::assertSame(1487285080.123456, $formatted[RegisteredClaims::EXPIRATION_TIME]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }
}
