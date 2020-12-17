<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Key;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Signer\Key;
use SodiumException;
use SplFileObject;
use Throwable;

use function assert;
use function is_string;
use function sodium_base642bin;

use const SODIUM_BASE64_VARIANT_ORIGINAL;

final class InMemory implements Key
{
    private string $contents;
    private string $passphrase;

    private function __construct(string $contents, string $passphrase)
    {
        $this->contents   = $contents;
        $this->passphrase = $passphrase;
    }

    public static function empty(): self
    {
        return new self('', '');
    }

    public static function plainText(string $contents, string $passphrase = ''): self
    {
        return new self($contents, $passphrase);
    }

    public static function base64Encoded(string $contents, string $passphrase = ''): self
    {
        try {
            $decoded = sodium_base642bin($contents, SODIUM_BASE64_VARIANT_ORIGINAL, '');
        } catch (SodiumException $sodiumException) {
            throw CannotDecodeContent::invalidBase64String($sodiumException);
        }

        return new self($decoded, $passphrase);
    }

    /** @throws FileCouldNotBeRead */
    public static function file(string $path, string $passphrase = ''): self
    {
        try {
            $file = new SplFileObject($path);
        } catch (Throwable $exception) {
            throw FileCouldNotBeRead::onPath($path, $exception);
        }

        $contents = $file->fread($file->getSize());
        assert(is_string($contents));

        return new self($contents, $passphrase);
    }

    public function contents(): string
    {
        return $this->contents;
    }

    public function passphrase(): string
    {
        return $this->passphrase;
    }
}
