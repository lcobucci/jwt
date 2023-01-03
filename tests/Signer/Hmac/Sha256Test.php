<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * @covers \Lcobucci\JWT\Signer\Hmac
 * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
 *
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 */
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
