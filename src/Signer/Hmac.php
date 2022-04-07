<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;

use function hash_equals;
use function hash_hmac;
use function mb_strlen;

abstract class Hmac implements Signer
{
    final public function sign(string $payload, Key $key): string
    {
        $actualKeyLength   = mb_strlen($key->contents(), '8bit');
        $expectedKeyLength = $this->minimumBytesLengthForKey();
        if ($actualKeyLength < $expectedKeyLength) {
            throw InvalidKeyProvided::tooShort($expectedKeyLength, $actualKeyLength);
        }

        return hash_hmac($this->algorithm(), $payload, $key->contents(), true);
    }

    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return hash_equals($expected, $this->sign($payload, $key));
    }

    abstract public function algorithm(): string;

    /** @return positive-int */
    abstract public function minimumBytesLengthForKey(): int;
}
