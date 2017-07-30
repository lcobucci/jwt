<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Rsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha512;

final class Sha512Bench extends RsaBench
{
    protected function signer(): Signer
    {
        return new Sha512();
    }
}
