<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\SafeString;
use Lcobucci\JWT\Signer\None;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"None"}) */
final class NoneBench extends SignerBench
{
    protected function signer(): Signer
    {
        return new None();
    }

    protected function signingKey(): Key
    {
        return SafeString::empty();
    }

    protected function verificationKey(): Key
    {
        return SafeString::empty();
    }
}
