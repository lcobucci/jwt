<?php

namespace Lcobucci\JWT\Validation\Constraint;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class LeewayCannotBeNegative extends InvalidArgumentException implements Exception
{
    /** @return self */
    public static function create()
    {
        return new self('Leeway cannot be negative');
    }
}
