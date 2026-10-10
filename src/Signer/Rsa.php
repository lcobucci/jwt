<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use const OPENSSL_KEYTYPE_RSA;

abstract readonly class Rsa extends OpenSSL
{
    private const int MINIMUM_KEY_LENGTH = 2048;

    final public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($key, $payload);
    }

    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key);
    }

    final protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
        if ($type !== OPENSSL_KEYTYPE_RSA) {
            throw InvalidKeyProvided::incompatibleKeyType(
                self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_RSA],
                self::KEY_TYPE_MAP[$type] ?? 'unknown',
            );
        }

        if ($lengthInBits < self::MINIMUM_KEY_LENGTH) {
            throw InvalidKeyProvided::tooShort(self::MINIMUM_KEY_LENGTH, $lengthInBits);
        }
    }
}
