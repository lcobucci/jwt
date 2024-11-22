<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\RsaPss;

use Lcobucci\JWT\Signer\RsaPss;

final class Sha384 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS384';
    }

    public function algorithm(): string
    {
        return 'sha384';
    }
}
