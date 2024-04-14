<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\UnixTimestampDates;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(UnixTimestampDates::class)]
final class UnixTimestampDatesTest extends TestCase
{
    #[PHPUnit\Test]
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

        $formatter = new UnixTimestampDates();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame(1487285080, $formatted[RegisteredClaims::ISSUED_AT]);
        self::assertSame(1487285080, $formatted[RegisteredClaims::NOT_BEFORE]);
        self::assertSame(1487285080, $formatted[RegisteredClaims::EXPIRATION_TIME]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }

    #[PHPUnit\Test]
    public function notAllDateClaimsNeedToBeConfigured(): void
    {
        $issuedAt   = new DateTimeImmutable('@1487285080');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');

        $claims = [
            RegisteredClaims::ISSUED_AT => $issuedAt,
            RegisteredClaims::EXPIRATION_TIME => $expiration,
            'testing' => 'test',
        ];

        $formatter = new UnixTimestampDates();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame(1487285080, $formatted[RegisteredClaims::ISSUED_AT]);
        self::assertSame(1487285080, $formatted[RegisteredClaims::EXPIRATION_TIME]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }
}
