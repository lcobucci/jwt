<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha384;
use Lcobucci\JWT\Signer\Key;

use const OPENSSL_ALGO_SHA384;

/**
 * @covers \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter
 * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha384
 * @covers \Lcobucci\JWT\Signer\Ecdsa
 * @covers \Lcobucci\JWT\Signer\OpenSSL
 * @covers \Lcobucci\JWT\Signer\InvalidKeyProvided
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class Sha384Test extends EcdsaTestCase
{
    protected function algorithm(): Ecdsa
    {
        return new Sha384($this->pointsManipulator);
    }

    protected function algorithmId(): string
    {
        return 'ES384';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    protected function pointLength(): int
    {
        return 96;
    }

    protected function keyLength(): int
    {
        return 384;
    }

    protected function verificationKey(): Key
    {
        return self::$ecdsaKeys['public_ec384'];
    }

    protected function signingKey(): Key
    {
        return self::$ecdsaKeys['private_ec384'];
    }

    /** {@inheritdoc} */
    protected function incompatibleKeys(): iterable
    {
        yield '256 bits' => ['private', 256];
        yield '521 bits' => ['private_ec512', 521];
    }
}
