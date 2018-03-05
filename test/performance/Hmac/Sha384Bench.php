<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha384;

final class Sha384Bench extends HmacBench
{
    protected function signer(): Signer
    {
        return new Sha384();
    }
}
