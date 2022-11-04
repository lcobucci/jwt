<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Ecdsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"ECDSA"}) */
final class Sha512Bench extends SignerBench
{
    protected function signer(): Signer
    {
        return new Sha512();
    }

    protected function signingKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/private-521.key');
    }

    protected function verificationKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/public-521.key');
    }
}
