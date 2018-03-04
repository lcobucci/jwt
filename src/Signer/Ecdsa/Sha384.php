<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;

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
    public function getAlgorithm(): string
    {
        return 'sha384';
    }
}
