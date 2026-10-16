<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha256;
use PHPUnit\Framework\Attributes as PHPUnit;

use const OPENSSL_ALGO_SHA256;

#[PHPUnit\CoversClass(Sha256::class)]
#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
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

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha256';
    }

    protected function tokenGeneratedByOtherLibs(): string
    {
        // Generated with Python's cryptography (PSS, MGF1 and salt length matching SHA-256)
        return 'eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0'
            . '.D7yu_SzfSRMaCRRI82yNYZ75hTBoiSllYh5vEMfhjmNRfc5p1VIf8JAyejM'
            . '8S-0k0lvPG2Qcdz4RfNZxfj9SYEiUU5owSsjIWHUGVCb3BKPL7fI4Gczj3Bc'
            . 'kF4PKjnfnPDQfM0-G62NdnDcDFDnk0CZqOHx2Xm60ZJK-tn6RNFFa7VfccWj'
            . 'i7hde7CVD4QXAA7w2DlF5ZMWnuBMY7NQVUU781ufhT3CBjL-gNz0HVe0cx87'
            . 'UaZ44dUHE4WcqtbwAYsl5RbylUf9YHMNs47bNZWowARR8vyjEET5MEy8zb8w'
            . 'VmIy5Xw9R99hqfGEONhw6VmnUBhrIgve-1kqmirwqCw';
    }
}
