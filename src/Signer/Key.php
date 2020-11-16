<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Key\FileCouldNotBeRead;
use SplFileObject;
use Throwable;

use function assert;
use function is_string;
use function strpos;
use function substr;

final class Key
{
    private string $content;
    private string $passphrase;

    public function __construct(string $content, string $passphrase = '')
    {
        $this->setContent($content);
        $this->passphrase = $passphrase;
    }

    /** @throws FileCouldNotBeRead */
    private function setContent(string $content): void
    {
        if (strpos($content, 'file://') === 0) {
            $content = $this->readFile($content);
        }

        $this->content = $content;
    }

    /** @throws FileCouldNotBeRead */
    private function readFile(string $path): string
    {
        $path = substr($path, 7);

        try {
            $file    = new SplFileObject($path);
            $content = $file->fread($file->getSize());
            assert(is_string($content));

            return $content;
        } catch (Throwable $exception) {
            throw FileCouldNotBeRead::onPath($path, $exception);
        }
    }

    public function getContent(): string
    {
        return $this->content;
    }

    public function getPassphrase(): string
    {
        return $this->passphrase;
    }
}
