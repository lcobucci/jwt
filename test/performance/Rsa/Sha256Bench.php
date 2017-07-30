<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Rsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Rsa\Sha256;

final class Sha256Bench extends RsaBench
{
    protected function signer(): Signer
    {
        return new Sha256();
    }
}
