<?php

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Signer\Key;

use function file_exists;

final class LocalFileReference extends Key
{
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
        if (! file_exists($path)) {
            throw FileCouldNotBeRead::onPath($path);
        }

        $key = new self('', $passphrase);
        $key->content = 'file://' . $path;

        return $key;
    }
}
