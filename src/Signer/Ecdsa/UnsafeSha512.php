<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\UnsafeEcdsa;

use const OPENSSL_ALGO_SHA512;

/** @deprecated Deprecated since v4.2 */
final class UnsafeSha512 extends UnsafeEcdsa
{
    public function algorithmId(): string
    {
        return 'ES512';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    public function pointLength(): int
    {
        return 132;
    }
}
