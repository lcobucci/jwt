<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer;

use Lcobucci\JWT\Signer\Falcon512;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\TestCase;

final class Falcon512Test extends TestCase
{
    private Falcon512 $signer;
    private InMemory $privateKey;
    private InMemory $publicKey;

    protected function setUp(): void
    {
        $this->signer = new Falcon512();
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($keyPair, $privateKeyPem);
        $publicKeyPem = openssl_pkey_get_details($keyPair)['key'];
        
        $this->privateKey = InMemory::plainText($privateKeyPem);
        $this->publicKey  = InMemory::plainText($publicKeyPem);
    }

    public function testShouldSignAndVerify(): void
    {
        $payload = 'test.payload';
        $signature = $this->signer->sign($payload, $this->privateKey);
        
        $this->assertNotEmpty($signature);
        $this->assertTrue(
            $this->signer->verify($signature, $payload, $this->publicKey)
        );
    }

    public function testShouldRejectTamperedSignature(): void
    {
        $payload = 'test.payload';
        $signature = $this->signer->sign($payload, $this->privateKey);
        $signature[10] = chr(ord($signature[10]) ^ 0xFF);
        
        $this->assertFalse(
            $this->signer->verify($signature, $payload, $this->publicKey)
        );
    }

    public function testShouldReturnAlgorithmId(): void
    {
        $this->assertSame('Falcon512', $this->signer->algorithmId());
    }
}
