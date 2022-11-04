<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha384;

/**
 * @covers \Lcobucci\JWT\Signer\Hmac
 * @covers \Lcobucci\JWT\Signer\Hmac\Sha384
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
final class Sha384Test extends HmacTestCase
{
    protected function algorithm(): Hmac
    {
        return new Sha384();
    }

    protected function expectedAlgorithmId(): string
    {
        return 'HS384';
    }

    protected function expectedMinimumBits(): int
    {
        return 384;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha384';
    }
}
