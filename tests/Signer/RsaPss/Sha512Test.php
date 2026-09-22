<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha512;
use PHPUnit\Framework\Attributes as PHPUnit;

use const OPENSSL_ALGO_SHA512;

#[PHPUnit\CoversClass(Sha512::class)]
#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha512Test extends RsaPssTestCase
{
    protected function algorithm(): RsaPss
    {
        return new Sha512();
    }

    protected function algorithmId(): string
    {
        return 'PS512';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA512;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha512';
    }

    protected function tokenGeneratedByOtherLibs(): string
    {
        // Generated with Python's cryptography (PSS, MGF1 and salt length matching SHA-512)
        return 'eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0'
            . '.vImU1GVQqeNkJPPhDHysO6Yxo4VgEDOKOyRv39KofGG0ahEnS0YcdRkKv1i'
            . '9EedWVQHhPW6Ju9AAvqZ1-XnyCan7nMsGIW6yNM_D2F9DjMU7491IfgBupIU'
            . 'O7xrztTOaLd6VJcPgPCOJO8pEY5OwG3SXOpGpJ6mNeV85i_gehDxNaYXmED9'
            . '9tcrUAvvtUydqAd9K-b8xwJbdIMoELogAK0lFeZlT3sToDtp8XZ2Ixf6hTpx'
            . 's-9_dnkQH4ZVEH4Qg1i1kPv4n1in0x6qVKHf1K0EhIeAm86AhCy05sblbQ2K'
            . 'U9d_CQ9TgZJ_XkkV42gr8txdSEtU5_QB1Up4H3aAOBw';
    }
}
