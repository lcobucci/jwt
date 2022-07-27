<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Rsa;

use Lcobucci\JWT\Signer\UnsafeRsa;

use const OPENSSL_ALGO_SHA512;

/** @deprecated Deprecated since v4.2 */
final class UnsafeSha512 extends UnsafeRsa
{
    public function algorithmId(): string
    {
        return 'RS512';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
