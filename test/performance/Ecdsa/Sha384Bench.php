<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Ecdsa;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\Sha384;

final class Sha384Bench extends EcdsaBench
{
    protected function signer(): Signer
    {
        return Sha384::create();
    }
}
