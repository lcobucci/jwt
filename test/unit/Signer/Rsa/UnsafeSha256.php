<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\OpenSSL;

use const OPENSSL_ALGO_SHA256;

/**
 * This is only meant for testing OpenSSL errors
 *
 * @internal
 */
final class UnsafeSha256 extends OpenSSL
{
    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    public function algorithmId(): string
    {
        return 'RS256';
    }

    public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($key->contents(), $key->passphrase(), $payload);
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key->contents());
    }
}
