<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;

final class Sha256Bench extends HmacBench
{
    protected function signer(): Signer
    {
        return new Sha256();
    }

    protected function createKey(): Key
    {
        return InMemory::base64Encoded('n5p7sBK+dvBmSKNlQIFrsuB1cnmnwsxGyWXPgRSZtWY=');
    }
}
