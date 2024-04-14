<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Encoding;

use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(UnifyAudience::class)]
final class UnifyAudienceTest extends TestCase
{
    #[PHPUnit\Test]
    public function nothingShouldBeDoneWhenAudienceIsNotSet(): void
    {
        $claims = ['testing' => 'test'];

        $formatter = new UnifyAudience();
        $formatted = $formatter->formatClaims($claims);

        self::assertSame('test', $formatted['testing']);
    }

    #[PHPUnit\Test]
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

    #[PHPUnit\Test]
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
