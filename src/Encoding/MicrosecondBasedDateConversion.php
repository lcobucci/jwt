<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Token\RegisteredClaims;

use function array_intersect;
use function array_keys;

final class MicrosecondBasedDateConversion implements ClaimsFormatter
{
    /** @inheritdoc */
    public function formatClaims(array $claims): array
    {
        foreach (array_intersect(RegisteredClaims::DATE_CLAIMS, array_keys($claims)) as $claim) {
            $claims[$claim] = $this->convertDate($claims[$claim]);
        }

        return $claims;
    }

    /** @return int|string */
    private function convertDate(DateTimeImmutable $date)
    {
        $seconds      = $date->format('U');
        $microseconds = $date->format('u');

        if ((int) $microseconds === 0) {
            return (int) $seconds;
        }

        return $seconds . '.' . $microseconds;
    }
}
