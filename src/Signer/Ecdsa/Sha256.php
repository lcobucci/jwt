<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA256;

final class Sha256 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 64;
    }
}
