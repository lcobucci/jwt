<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha384;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(Sha384::class)]
#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha384Test extends RsaPssTestCase
{
    protected function algorithm(): RsaPss
    {
        return new Sha384();
    }

    protected function algorithmId(): string
    {
        return 'PS384';
    }

    protected function signatureAlgorithm(): string
    {
        return 'sha384';
    }
}
