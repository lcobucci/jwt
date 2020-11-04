<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Token\RegisteredClaims;

use function count;
use function current;

final class UnifyAudience implements ClaimsFormatter
{
    /** @inheritdoc */
    public function formatClaims(array $claims): array
    {
        if (! isset($claims[RegisteredClaims::AUDIENCE]) || count($claims[RegisteredClaims::AUDIENCE]) !== 1) {
            return $claims;
        }

        $claims[RegisteredClaims::AUDIENCE] = current($claims[RegisteredClaims::AUDIENCE]);

        return $claims;
    }
}
