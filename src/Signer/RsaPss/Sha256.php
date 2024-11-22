<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\RsaPss;

use Lcobucci\JWT\Signer\RsaPss;

final class Sha256 extends RsaPss
{
    public function algorithmId(): string
    {
        return 'PS256';
    }

    public function algorithm(): string
    {
        return 'sha256';
    }
}
