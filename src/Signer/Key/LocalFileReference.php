<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Signer\Key;

use function file_exists;

final class LocalFileReference implements Key
{
    private string $path;
    private string $passphrase;

    private function __construct(string $path, string $passphrase)
    {
        $this->path       = $path;
        $this->passphrase = $passphrase;
    }

    /** @throws FileCouldNotBeRead */
    public static function file(string $path, string $passphrase = ''): self
    {
        if (! file_exists($path)) {
            throw FileCouldNotBeRead::onPath($path);
        }

        return new self($path, $passphrase);
    }

    public function contents(): string
    {
        return 'file://' . $this->path;
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }
}
