<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use const OPENSSL_KEYTYPE_RSA;

/** @deprecated Deprecated since v4.2 */
abstract class UnsafeRsa extends OpenSSL
{
    final public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($key->contents(), $key->passphrase(), $payload);
    }

    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key->contents());
    }

    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    final protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
        if ($type !== OPENSSL_KEYTYPE_RSA) {
            throw InvalidKeyProvided::incompatibleKeyType(
                self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_RSA],
                self::KEY_TYPE_MAP[$type],
            );
        }
    }
}
