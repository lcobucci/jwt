<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Exception;
use LogicException;

final class ExtSodiumMissing extends LogicException implements Exception
{
    public static function forEddsa(): self
    {
        return new self('EdDSA signer requires PHP extension ext-sodium to be installed');
    }

    public static function forBlake2b(): self
    {
        return new self('BLAKE2B signer requires PHP extension ext-sodium to be installed');
    }
}
