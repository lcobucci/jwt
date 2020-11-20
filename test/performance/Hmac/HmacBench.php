<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SignerBench;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"Hmac"}) */
abstract class HmacBench extends SignerBench
{
    private const ENCODED_KEY = 'hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG+Onbc6mxCcYg';

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
