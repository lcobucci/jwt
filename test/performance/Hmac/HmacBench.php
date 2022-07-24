<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"Hmac"}) */
abstract class HmacBench extends SignerBench
{
    protected function signingKey(): Key
    {
        return $this->createKey();
    }

    protected function verificationKey(): Key
    {
        return $this->createKey();
    }

    abstract protected function createKey(): Key;
}
