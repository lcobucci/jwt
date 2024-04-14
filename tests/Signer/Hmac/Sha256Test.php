<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(Hmac::class)]
#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha256Test extends HmacTestCase
{
    protected function algorithm(): Hmac
    {
        return new Sha256();
    }

    protected function expectedAlgorithmId(): string
    {
        return 'HS256';
    }

    protected function expectedMinimumBits(): int
    {
        return 256;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha256';
    }
}
