<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark\Hmac;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;

final class Sha384Bench extends HmacBench
{
    protected function signer(): Signer
    {
        return new Sha384();
    }

    protected function createKey(): Key
    {
        return InMemory::base64Encoded('kNUb8KvJC+fvhPzIuimwWHleES3AAnUjI+UIWZyor5HT33st9KIjfPkgtfu60UL2');
    }
}
