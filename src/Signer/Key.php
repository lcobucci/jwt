<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\InvalidArgument;
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

    /** @throws InvalidArgument */
    private function setContent(string $content): void
    {
        if (strpos($content, 'file://') === 0) {
            $content = $this->readFile($content);
        }

        $this->content = $content;
    }

    /** @throws InvalidArgument */
    private function readFile(string $path): string
    {
        try {
            $file    = new SplFileObject(substr($path, 7));
            $content = $file->fread($file->getSize());
            assert(is_string($content));

            return $content;
        } catch (Throwable $exception) {
            throw new InvalidArgument('You must provide a valid key file', $exception->getCode(), $exception);
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
