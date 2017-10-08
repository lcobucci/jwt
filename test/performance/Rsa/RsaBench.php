<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Rsa;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\SignerBench;

abstract class RsaBench extends SignerBench
{
    protected function signingKey(): Key
    {
        return new Key('file://' . __DIR__ . '/private.key');
    }

    protected function verificationKey(): Key
    {
        return new Key('file://' . __DIR__ . '/public.key');
    }
}
