<?php

namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class InvalidTokenStructure extends InvalidArgumentException implements Exception
{
    /** @return self */
    public static function missingOrNotEnoughSeparators()
    {
        return new self('The JWT string must have two dots');
    }

    /**
     * @param string $part
     *
     * @return self
     */
    public static function arrayExpected($part)
    {
        return new self($part . ' must be an array');
    }

    /**
     * @param string $value
     *
     * @return self
     */
    public static function dateIsNotParseable($value)
    {
        return new self('Value is not in the allowed date format: ' . $value);
    }
}
