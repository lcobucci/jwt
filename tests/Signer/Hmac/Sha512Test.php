<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha512;

/**
 * @covers \Lcobucci\JWT\Signer\Hmac
 * @covers \Lcobucci\JWT\Signer\Hmac\Sha512
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class Sha512Test extends HmacTestCase
{
    protected function algorithm(): Hmac
    {
        return new Sha512();
    }

    protected function expectedAlgorithmId(): string
    {
        return 'HS512';
    }

    protected function expectedMinimumBits(): int
    {
        return 512;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha512';
    }
}
