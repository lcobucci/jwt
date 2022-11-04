<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Blake2b;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"Blake2B"}) */
final class Blake2bBench extends SignerBench
{
    private const ENCODED_KEY = 'b6DNRcX2SFapbICe6lXWYoOZA+JXL/dvkfWiv2hJv3Y=';

    protected function signer(): Signer
    {
        return new Blake2b();
    }

    protected function signingKey(): Key
    {
        return $this->createKey();
    }

    protected function verificationKey(): Key
    {
        return $this->createKey();
    }

    private function createKey(): Key
    {
        return InMemory::base64Encoded(self::ENCODED_KEY);
    }
}
