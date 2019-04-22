<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use const OPENSSL_KEYTYPE_RSA;

abstract class Rsa extends OpenSSL
{
    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($key->getContent(), $key->getPassphrase(), $payload);
    }

    /**
     * {@inheritdoc}
     */
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key->getContent());
    }

    final public function getKeyType(): int
    {
        return OPENSSL_KEYTYPE_RSA;
    }
}
