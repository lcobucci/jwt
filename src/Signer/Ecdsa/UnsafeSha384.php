<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\UnsafeEcdsa;

use const OPENSSL_ALGO_SHA384;

/** @deprecated Deprecated since v4.2 */
final class UnsafeSha384 extends UnsafeEcdsa
{
    public function algorithmId(): string
    {
        return 'ES384';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    public function pointLength(): int
    {
        return 96;
    }
}
