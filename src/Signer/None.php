<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;

final class None implements Signer
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId(): string
    {
        return 'none';
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, Key $key): string
    {
        return '';
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $expected === '';
    }
}
