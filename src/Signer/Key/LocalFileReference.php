<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Signer\Key;

use function file_exists;
use function str_starts_with;
use function substr;

/** @deprecated please use {@see InMemory} instead */
final class LocalFileReference implements Key
{
    private const PATH_PREFIX = 'file://';

    private string $contents;

    private function __construct(private string $path, private string $passphrase)
    {
    }

    /** @throws FileCouldNotBeRead */
    public static function file(string $path, string $passphrase = ''): self
    {
        if (str_starts_with($path, self::PATH_PREFIX)) {
            $path = substr($path, 7);
        }

        if (! file_exists($path)) {
            throw FileCouldNotBeRead::onPath($path);
        }

        return new self($path, $passphrase);
    }

    public function contents(): string
    {
        if (! isset($this->contents)) {
            $this->contents = InMemory::file($this->path)->contents();
        }

        return $this->contents;
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }
}
