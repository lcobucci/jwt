<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha384;

use const OPENSSL_ALGO_SHA384;

/**
 * @covers \Lcobucci\JWT\Signer\Rsa\Sha384
 * @covers \Lcobucci\JWT\Signer\Rsa
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
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
