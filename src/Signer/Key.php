<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use SplFileObject;
use Throwable;
use function assert;
use function is_string;

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
        $this->content    = $content;
        $this->passphrase = $passphrase;
    }

    /**
     * @throws InvalidArgumentException
     */
    public static function fromFile(string $filename, string $passphrase = ''): self
    {
        try {
            $file    = new SplFileObject($filename);
            $content = $file->fread($file->getSize());
            assert(is_string($content));
        } catch (Throwable $exception) {
            throw new InvalidArgumentException('You must provide a valid key file', $exception->getCode(), $exception);
        }

        return new self($content, $passphrase);
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
