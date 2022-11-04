<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Ecdsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"ECDSA"}) */
final class Sha256Bench extends SignerBench
{
    protected function signer(): Signer
    {
        return new Sha256();
    }

    protected function signingKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/private-256.key');
    }

    protected function verificationKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/public-256.key');
    }
}
