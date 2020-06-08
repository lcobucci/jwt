<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;

use const OPENSSL_ALGO_SHA512;

final class Sha512 extends Ecdsa
{
    public function getAlgorithmId(): string
    {
        return 'ES512';
    }

    public function getAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    public function getKeyLength(): int
    {
        return 132;
    }
}
