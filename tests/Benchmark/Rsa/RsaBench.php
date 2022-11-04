<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark\Rsa;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Tests\Benchmark\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"RSA"}) */
abstract class RsaBench extends SignerBench
{
    protected function signingKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/private.key');
    }

    protected function verificationKey(): Key
    {
        return Key\InMemory::file(__DIR__ . '/public.key');
    }
}
