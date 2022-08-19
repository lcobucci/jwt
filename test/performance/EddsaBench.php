<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use PhpBench\Benchmark\Metadata\Annotations\Groups;

/** @Groups({"EdDSA"}) */
final class EddsaBench extends SignerBench
{
    protected function signer(): Signer
    {
        return new Eddsa();
    }

    protected function signingKey(): Key
    {
        return InMemory::base64Encoded(
            'dv6B60wqqFVDpt8+TnW7T6NtRpVQjiQP/PoqonDWBZkVboQttTfzXux+WnZeacJDcklMgyKFHVFy1C7tVDvcWA==',
        );
    }

    protected function verificationKey(): Key
    {
        return InMemory::base64Encoded('FW6ELbU3817sflp2XmnCQ3JJTIMihR1RctQu7VQ73Fg=');
    }
}
