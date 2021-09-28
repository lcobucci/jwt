<?php

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Signer\Key;

use function file_exists;
use function strpos;
use function substr;

/** @deprecated Use \Lcobucci\JWT\Signer\Key\InMemory::file() instead */
final class LocalFileReference extends Key
{
    const PATH_PREFIX = 'file://';

    /**
     * @param string $path
     * @param string $passphrase
     *
     * @return self
     *
     * @throws FileCouldNotBeRead
     */
    public static function file($path, $passphrase = '')
    {
        if (strpos($path, self::PATH_PREFIX) === 0) {
            $path = substr($path, 7);
        }

        return new self(self::PATH_PREFIX . $path, $passphrase);
    }
}
