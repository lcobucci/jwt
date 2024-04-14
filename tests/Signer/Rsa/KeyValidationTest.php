<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Rsa;

use Lcobucci\JWT\Signer\CannotSignPayload;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\OpenSSL;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function openssl_error_string;

use const OPENSSL_ALGO_SHA256;
use const PHP_EOL;

#[PHPUnit\CoversClass(OpenSSL::class)]
#[PHPUnit\CoversClass(CannotSignPayload::class)]
#[PHPUnit\UsesClass(InMemory::class)]
final class KeyValidationTest extends TestCase
{
    #[PHPUnit\After]
    public function clearOpenSSLErrors(): void
    {
        // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedWhile
        while (openssl_error_string()) {
        }
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsInvalid(): void
    {
        $key = <<<'KEY'
-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQC4MRKSVsq5XnRBrJoX6+rnAgMBAAECECO8SZkgw6Yg66A6SUly/3kC
CQDtPXZtCQWJuwIJAMbBu17GDOrFAggopfhNlFcjkwIIVjb7G+U0/TECCEERyvxP
TWdN
-----END RSA PRIVATE KEY-----
KEY;

        $this->expectException(CannotSignPayload::class);
        $this->expectExceptionMessage('There was an error while creating the signature:' . PHP_EOL . '* error:');

        $this->algorithm()->sign('testing', InMemory::plainText($key));
    }

    private function algorithm(): OpenSSL
    {
        return new class () extends OpenSSL
        {
            // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter.UnusedParameter
            protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
            {
            }

            public function algorithm(): int
            {
                return OPENSSL_ALGO_SHA256;
            }

            public function algorithmId(): string
            {
                return 'RS256';
            }

            public function sign(string $payload, Key $key): string
            {
                return $this->createSignature($key->contents(), $key->passphrase(), $payload);
            }

            public function verify(string $expected, string $payload, Key $key): bool
            {
                return $this->verifySignature($expected, $payload, $key->contents());
            }
        };
    }
}
