<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Encoding\UnifyAudience */
final class UnifyAudienceTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::formatClaims
     */
    public function nothingShouldBeDoneWhenAudienceIsNotSet(): void
    {
        $claims = ['testing' => 'test'];

        $formatter = new UnifyAudience();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame('test', $formatted['testing']);
    }

    /**
     * @test
     *
     * @covers ::formatClaims
     */
    public function audienceShouldBeFormattedAsSingleStringWhenOneValueIsUsed(): void
    {
        $claims = [
            RegisteredClaims::AUDIENCE => ['test1'],
            'testing' => 'test',
        ];

        $formatter = new UnifyAudience();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame('test1', $formatted[RegisteredClaims::AUDIENCE]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }

    /**
     * @test
     *
     * @covers ::formatClaims
     */
    public function audienceShouldBeFormattedAsArrayWhenMultipleValuesAreUsed(): void
    {
        $claims = [
            RegisteredClaims::AUDIENCE => ['test1', 'test2', 'test3'],
            'testing' => 'test',
        ];

        $formatter = new UnifyAudience();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame(['test1', 'test2', 'test3'], $formatted[RegisteredClaims::AUDIENCE]);
        self::assertSame('test', $formatted['testing']); // this should remain untouched
    }
}
