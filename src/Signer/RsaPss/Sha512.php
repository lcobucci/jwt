<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\RsaPss;

use Lcobucci\JWT\Signer\RsaPss;

use const OPENSSL_ALGO_SHA512;

final readonly class Sha512 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS512';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
