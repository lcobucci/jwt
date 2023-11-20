<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

final class FakeSigner implements Signer
{
    /** @param non-empty-string $signature */
    public function __construct(private readonly string $signature)
    {
    }

    public function algorithmId(): string
    {
        return 'FAKE-' . $this->signature;
    }

    public function sign(string $payload, Key $key): string
    {
        return $this->signature . '-' . $key->contents();
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->signature . '-' . $key->contents() === $expected;
    }
}
