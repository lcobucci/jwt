<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha384;
use PHPUnit\Framework\Attributes as PHPUnit;

use const OPENSSL_ALGO_SHA384;

#[PHPUnit\CoversClass(Sha384::class)]
#[PHPUnit\CoversClass(Rsa::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha384Test extends RsaTestCase
{
    protected function algorithm(): Rsa
    {
        return new Sha384();
    }

    protected function algorithmId(): string
    {
        return 'RS384';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }
}
