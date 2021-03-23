<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Plain;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Lcobucci\JWT\Configuration
 * @covers \Lcobucci\JWT\Encoding\JoseEncoder
 * @covers \Lcobucci\JWT\Encoding\ChainedFormatter
 * @covers \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
 * @covers \Lcobucci\JWT\Encoding\UnifyAudience
 * @covers \Lcobucci\JWT\Token\Builder
 * @covers \Lcobucci\JWT\Token\Parser
 * @covers \Lcobucci\JWT\Token\Plain
 * @covers \Lcobucci\JWT\Token\DataSet
 * @covers \Lcobucci\JWT\Token\Signature
 * @covers \Lcobucci\JWT\Signer\Key\InMemory
 * @covers \Lcobucci\JWT\Signer\None
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
 */
final class TimeFractionPrecisionTest extends TestCase
{
    /**
     * @test
     * @dataProvider datesWithPotentialRoundingIssues
     */
    public function timeFractionsPrecisionsAreRespected(string $timeFraction): void
    {
        $config = Configuration::forUnsecuredSigner();

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
    public function datesWithPotentialRoundingIssues(): iterable
    {
        yield ['1613938511.017448'];
        yield ['1613938511.023691'];
        yield ['1613938511.018045'];
        yield ['1616074725.008455'];
    }

    /**
     * @test
     * @dataProvider timeFractionConversions
     *
     * @param float|int|string $issuedAt
     */
    public function typeConversionDoesNotCauseParsingErrors($issuedAt, string $timeFraction): void
    {
        $encoder = new JoseEncoder();
        $headers = $encoder->base64UrlEncode($encoder->jsonEncode(['typ' => 'JWT', 'alg' => 'none']));
        $claims  = $encoder->base64UrlEncode($encoder->jsonEncode(['iat' => $issuedAt]));

        $config      = Configuration::forUnsecuredSigner();
        $parsedToken = $config->parser()->parse($headers . '.' . $claims . '.');

        self::assertInstanceOf(Plain::class, $parsedToken);
        self::assertSame($timeFraction, $parsedToken->claims()->get('iat')->format('U.u'));
    }

    /** @return iterable<array{0: float|int|string, 1: string}> */
    public function timeFractionConversions(): iterable
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
