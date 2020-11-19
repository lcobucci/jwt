<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Ecdsa;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"ECDSA"}) */
abstract class EcdsaBench extends SignerBench
{
    protected function signingKey(): Key
    {
        return LocalFileReference::file(__DIR__ . '/private.key');
    }

    protected function verificationKey(): Key
    {
        return LocalFileReference::file(__DIR__ . '/public.key');
    }
}
