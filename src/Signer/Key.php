<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use SplFileObject;
use Throwable;
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
        try {
            $file    = new SplFileObject(substr($content, 7));

            return $file->fread($file->getSize());
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('You must inform a valid key file', $exception->getCode(), $exception);
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
