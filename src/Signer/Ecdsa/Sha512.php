<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA512;

final class Sha512 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES512';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 132;
    }
}
