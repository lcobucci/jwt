<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha512;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(Sha512::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha512Test extends RsaPssTestCase
{
    protected function algorithm(): RsaPss
    {
        return new Sha512();
    }

    protected function algorithmId(): string
    {
        return 'PS512';
    }

    protected function signatureAlgorithm(): string
    {
        return 'sha512';
    }
}
