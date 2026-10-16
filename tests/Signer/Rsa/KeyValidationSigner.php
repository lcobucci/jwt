<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\OpenSSL;

use const OPENSSL_ALGO_SHA256;
use const OPENSSL_PKCS1_PADDING;

final readonly class KeyValidationSigner extends OpenSSL
{
    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function padding(): int
    {
        return OPENSSL_PKCS1_PADDING;
    }

    public function algorithmId(): string
    {
        return 'RS256';
    }

    public function sign(string $payload, Key $key): string
    {
        return $this->createSignature($key, $payload);
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature($expected, $payload, $key);
    }
}
