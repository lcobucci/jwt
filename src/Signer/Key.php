<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use function file_get_contents;
use function is_readable;
use function strpos;
use function substr;

final class Key
{
    /**
     * @var string
     */
    private $content;

    /**
     * @var string
     */
    private $passphrase;

    public function __construct(string $content, string $passphrase = '')
    {
        $this->setContent($content);
        $this->passphrase = $passphrase;
    }

    /**
     * @throws InvalidArgumentException
     */
    private function setContent(string $content): void
    {
        if (strpos($content, 'file://') === 0) {
            $content = $this->readFile($content);
        }

        $this->content = $content;
    }

    /**
     * @throws \InvalidArgumentException
     */
    private function readFile(string $content): string
    {
        $file = substr($content, 7);

        if (! is_readable($file)) {
            throw new \InvalidArgumentException('You must inform a valid key file');
        }

        return file_get_contents($file);
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
