<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;
use Throwable;

final class FileCouldNotBeRead extends InvalidArgumentException implements Exception
{
    public static function onPath(string $path, Throwable $cause): self
    {
        return new self(
            'The path "' . $path . '" does not contain a valid key file',
            $cause->getCode(),
            $cause
        );
    }
}
