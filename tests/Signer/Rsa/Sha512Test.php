<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha512;

use const OPENSSL_ALGO_SHA512;

/**
 * @covers \Lcobucci\JWT\Signer\Rsa\Sha512
 * @covers \Lcobucci\JWT\Signer\Rsa
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class Sha512Test extends RsaTestCase
{
    protected function algorithm(): Rsa
    {
        return new Sha512();
    }

    protected function algorithmId(): string
    {
        return 'RS512';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }
}
