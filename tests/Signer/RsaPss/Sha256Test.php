<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha256;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha256Test extends RsaPssTestCase
{
    protected function algorithm(): RsaPss
    {
        return new Sha256();
    }

    protected function algorithmId(): string
    {
        return 'PS256';
    }

    protected function signatureAlgorithm(): string
    {
        return 'sha256';
    }
}
