<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use DateTimeImmutable;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Token\RegisteredClaims;

use function array_intersect;
use function array_keys;
use function count;
use function current;

final class DefaultClaimsFormatter implements ClaimsFormatter
{
    /**
     * {@inheritdoc}
     */
    public function formatClaims(array $claims): array
    {
        if (isset($claims[RegisteredClaims::AUDIENCE]) && count($claims[RegisteredClaims::AUDIENCE]) === 1) {
            $claims[RegisteredClaims::AUDIENCE] = current($claims[RegisteredClaims::AUDIENCE]);
        }

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
