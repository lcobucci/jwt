<?php

namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class UnsupportedHeaderFound extends InvalidArgumentException implements Exception
{
    /** @return self */
    public static function encryption()
    {
        return new self('Encryption is not supported yet');
    }
}
