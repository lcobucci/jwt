<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\RsaPss;

use Lcobucci\JWT\Signer\RsaPss;

use const OPENSSL_ALGO_SHA384;

final readonly class Sha384 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS384';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
}
