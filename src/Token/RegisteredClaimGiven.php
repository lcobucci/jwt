<?php

namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

use function sprintf;

final class RegisteredClaimGiven extends InvalidArgumentException implements Exception
{
    const DEFAULT_MESSAGE = 'Builder#withClaim() is meant to be used for non-registered claims, '
                                  . 'check the documentation on how to set claim "%s"';

    /**
     * @param string $name
     *
     * @return self
     */
    public static function forClaim($name)
    {
        return new self(sprintf(self::DEFAULT_MESSAGE, $name));
    }
}
