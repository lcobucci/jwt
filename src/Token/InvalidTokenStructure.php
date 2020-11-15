<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class InvalidTokenStructure extends InvalidArgumentException implements Exception
{
    public static function missingOrNotEnoughSeparators(): self
    {
        return new self('The JWT string must have two dots');
    }

    public static function arrayExpected(string $part): self
    {
        return new self($part . ' must be an array');
    }

    public static function dateIsNotParseable(string $value): self
    {
        return new self('Value is not in the allowed date format: ' . $value);
    }
}
