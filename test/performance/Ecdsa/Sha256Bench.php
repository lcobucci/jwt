<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Ecdsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;

final class Sha256Bench extends EcdsaBench
{
    protected function signer(): Signer
    {
        return Sha256::create();
    }
}
