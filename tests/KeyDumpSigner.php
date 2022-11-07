<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

final class KeyDumpSigner implements Signer
{
    public function algorithmId(): string
    {
        return 'keydump';
    }

    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    public function sign(string $payload, Key $key): string
    {
        return $key->contents();
    }

    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $expected === $key->contents();
    }
}
