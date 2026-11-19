<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use NoDiscard;

interface ClaimsFormatter
{
    /**
     * @param array<non-empty-string, mixed> $claims
     *
     * @return array<non-empty-string, mixed>
     */
    #[NoDiscard]
    public function formatClaims(array $claims): array;
}
