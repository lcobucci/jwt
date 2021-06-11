<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\JWT\Exception;
use RuntimeException;

final class TimeRequired extends RuntimeException implements Exception
{
    public static function expiresAtRequired(): self
    {
        return new self('The token requires an expiration time to be issued, add it by calling ::expiresAt');
    }

    public static function issuedAtRequired(): self
    {
        return new self('The token requires an issue time to be issued, add it by calling ::issuedAt');
    }

    public static function canOnlyBeUsedAfterRequired(): self
    {
        return new self(
            'The token requires an starting usage time to be issued, add it by calling ::canOnlyBeUsedAfter'
        );
    }
}
