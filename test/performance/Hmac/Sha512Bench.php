<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha512;

final class Sha512Bench extends HmacBench
{
    protected function signer(): Signer
    {
        return new Sha512();
    }
}
