<?php

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Signer\Key;

use function file_exists;
use function strpos;
use function substr;

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

        if (! file_exists($path)) {
            throw FileCouldNotBeRead::onPath($path);
        }

        $key = new self('', $passphrase);
        $key->content = self::PATH_PREFIX . $path;

        return $key;
    }
}
