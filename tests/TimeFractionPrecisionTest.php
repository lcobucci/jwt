<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Plain;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\CoversClass(Encoding\JoseEncoder::class)]
#[PHPUnit\CoversClass(Encoding\ChainedFormatter::class)]
#[PHPUnit\CoversClass(Encoding\MicrosecondBasedDateConversion::class)]
#[PHPUnit\CoversClass(Encoding\UnifyAudience::class)]
#[PHPUnit\CoversClass(Token\Builder::class)]
#[PHPUnit\CoversClass(Token\Parser::class)]
#[PHPUnit\CoversClass(Token\Plain::class)]
#[PHPUnit\CoversClass(Token\DataSet::class)]
#[PHPUnit\CoversClass(Token\Signature::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
final class TimeFractionPrecisionTest extends TestCase
{
    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('datesWithPotentialRoundingIssues')]
    public function timeFractionsPrecisionsAreRespected(string $timeFraction): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        $issuedAt = DateTimeImmutable::createFromFormat('U.u', $timeFraction);

        self::assertInstanceOf(DateTimeImmutable::class, $issuedAt);
        self::assertSame($timeFraction, $issuedAt->format('U.u'));

        $token = $config->builder()
            ->issuedAt($issuedAt)
            ->getToken($config->signer(), $config->signingKey());

        $parsedToken = $config->parser()->parse($token->toString());

        self::assertInstanceOf(Plain::class, $parsedToken);
        self::assertSame($timeFraction, $parsedToken->claims()->get('iat')->format('U.u'));
    }

    /** @return iterable<string[]> */
    public static function datesWithPotentialRoundingIssues(): iterable
    {
        yield ['1613938511.017448'];
        yield ['1613938511.023691'];
        yield ['1613938511.018045'];
        yield ['1616074725.008455'];
    }

    #[PHPUnit\Test]
    #[PHPUnit\DataProvider('timeFractionConversions')]
    public function typeConversionDoesNotCauseParsingErrors(float|int|string $issuedAt, string $timeFraction): void
    {
        $encoder = new Encoding\JoseEncoder();
        $headers = $encoder->base64UrlEncode($encoder->jsonEncode(['typ' => 'JWT', 'alg' => 'none']));
        $claims  = $encoder->base64UrlEncode($encoder->jsonEncode(['iat' => $issuedAt]));

        $config      = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $parsedToken = $config->parser()->parse($headers . '.' . $claims . '.cHJpdmF0ZQ');

        self::assertInstanceOf(Token\Plain::class, $parsedToken);
        self::assertSame($timeFraction, $parsedToken->claims()->get('iat')->format('U.u'));
    }

    /** @return iterable<array{0: float|int|string, 1: string}> */
    public static function timeFractionConversions(): iterable
    {
        yield [1616481863.528781890869140625, '1616481863.528782'];
        yield [1616497608.0510409, '1616497608.051041'];
        yield [1616536852.1000001, '1616536852.100000'];
        yield [1616457346.3878131, '1616457346.387813'];
        yield [1616457346.0, '1616457346.000000'];

        yield [1616457346, '1616457346.000000'];

        yield ['1616481863.528781890869140625', '1616481863.528782'];
        yield ['1616497608.0510409', '1616497608.051041'];
        yield ['1616536852.1000001', '1616536852.100000'];
        yield ['1616457346.3878131', '1616457346.387813'];
        yield ['1616457346.0', '1616457346.000000'];
        yield ['1616457346', '1616457346.000000'];
    }
}
