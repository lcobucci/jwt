<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Falcon;

use Lcobucci\JWT\Signer\Falcon\Falcon1024Signer;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Lcobucci\JWT\Signer\Falcon\Falcon1024Signer
 */
final class Falcon1024SignerTest extends TestCase
{
    private Falcon1024Signer $signer;

    protected function setUp(): void
    {
        $this->signer = new Falcon1024Signer();
    }

    /**
     * @covers ::algorithmId
     */
    public function testAlgorithmId(): void
    {
        $this->assertSame('Falcon-1024', $this->signer->algorithmId());
    }

    /**
     * @covers ::sign
     * @covers ::verify
     * @covers ::validateKey
     * @covers ::extractKeyData
     */
    public function testSignAndVerify(): void
    {
        $payload = 'test.payload';
        $key = InMemory::plainText(str_repeat('a', 2305));

        $signature = $this->signer->sign($payload, $key);

        $this->assertNotEmpty($signature);
        $this->assertTrue(
            $this->signer->verify($signature, $payload, $key)
        );
    }

    /**
     * @covers ::verify
     * @covers ::sign
     * @covers ::validateKey
     * @covers ::extractKeyData
     */
    public function testRejectsTamperedSignature(): void
    {
        $payload = 'test.payload';
        $key = InMemory::plainText(str_repeat('a', 2305));

        $signature = $this->signer->sign($payload, $key);
        $signature[0] = chr(ord($signature[0]) ^ 0xFF);

        $this->assertFalse(
            $this->signer->verify($signature, $payload, $key)
        );
    }

    /**
     * @covers ::verify
     * @covers ::sign
     * @covers ::validateKey
     * @covers ::extractKeyData
     */
    public function testRejectsWrongKey(): void
    {
        $payload = 'test.payload';
        $key1 = InMemory::plainText(str_repeat('a', 2305));
        $key2 = InMemory::plainText(str_repeat('b', 2305));

        $signature = $this->signer->sign($payload, $key1);

        $this->assertFalse(
            $this->signer->verify($signature, $payload, $key2)
        );
    }

    /**
     * @covers ::validateKey
     */
    public function testRejectsInvalidKey(): void
    {
        $this->expectException(InvalidKeyProvided::class);

        $this->signer->sign('payload', InMemory::plainText(''));
    }
}
