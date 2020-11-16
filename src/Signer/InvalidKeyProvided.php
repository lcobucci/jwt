<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Exception;

final class InvalidKeyProvided extends InvalidArgumentException implements Exception
{
    public static function cannotBeParsed(string $details): self
    {
        return new self('It was not possible to parse your key, reason: ' . $details);
    }

    public static function incompatibleKey(): self
    {
        return new self('This key is not compatible with this signer');
    }
}
