<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use const OPENSSL_ALGO_SHA384;

final class Sha384 extends Ecdsa
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'ES384';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyLength(): int
    {
        return 96;
    }
}
