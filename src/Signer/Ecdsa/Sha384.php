<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA384;

final class Sha384 extends Ecdsa
{
    public function getAlgorithmId(): string
    {
        return 'ES384';
    }

    public function getAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    public function getKeyLength(): int
    {
        return 96;
    }
}
