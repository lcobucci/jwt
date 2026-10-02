<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\RsaPss;

use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use Lcobucci\JWT\Signer\RsaPss;
use Lcobucci\JWT\Signer\RsaPss\Sha384;
use PHPUnit\Framework\Attributes as PHPUnit;

use const OPENSSL_ALGO_SHA384;

#[PHPUnit\CoversClass(Sha384::class)]
#[PHPUnit\CoversClass(RsaPss::class)]
#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class Sha384Test extends RsaPssTestCase
{
    protected function algorithm(): RsaPss
    {
        return new Sha384();
    }

    protected function algorithmId(): string
    {
        return 'PS384';
    }

    protected function signatureAlgorithm(): int
    {
        return OPENSSL_ALGO_SHA384;
    }

    protected function hashAlgorithm(): string
    {
        return 'sha384';
    }

    protected function tokenGeneratedByOtherLibs(): string
    {
        // Generated with Python's cryptography (PSS, MGF1 and salt length matching SHA-384)
        return 'eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0'
            . '.ewmTu5_w26BacmbidiBqYYHP2-nF8dSZNxZWmyGQgIb7zKCqTM3_T74V2bE'
            . 'JWk8IaqK7KY9phmmWFigTGfR8ZqZev25g_dRvgrOZfwhVqeoddYaGCaRN47f'
            . 'u07ru2_0pVKorvpuFppU_9pNgD4Sz4SMYO2uLPYnY6xU6ohd7ATVSpvHbpVu'
            . 'WEGFXLoU0mMFBcOSjJk2BmS7bfsyTUlzbC-VF5catx5HcGZlFI2teYOedHFn'
            . 'dW0kHWts0ODKW7JXBVRMuE2kXFBOrRc2Jcyu41Jy_HwqDDdI-k95iTB_AONk'
            . 'reHySnV_W8Tq1WF7SZQuQqhRs9Us8cd85UKDLI_uyig';
    }
}
