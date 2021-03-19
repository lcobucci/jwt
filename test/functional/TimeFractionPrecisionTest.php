<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
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
}
