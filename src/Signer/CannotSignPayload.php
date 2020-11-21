<?php

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class CannotSignPayload extends InvalidArgumentException implements Exception
{
    /**
     * @pararm string $error
     *
     * @return self
     */
    public static function errorHappened($error)
    {
        return new self('There was an error while creating the signature: ' . $error);
    }
}
