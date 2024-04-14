<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer\Hmac;

use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;
use function hash_equals;
use function hash_hmac;
use function is_int;
use function random_bytes;
use function sprintf;
use function strlen;

abstract class HmacTestCase extends TestCase
{
    abstract protected function algorithm(): Hmac;

    abstract protected function hashAlgorithm(): string;

    abstract protected function expectedAlgorithmId(): string;

    abstract protected function expectedMinimumBits(): int;

    #[PHPUnit\Test]
    public function algorithmIdMustBeCorrect(): void
    {
        self::assertEquals($this->expectedAlgorithmId(), $this->algorithm()->algorithmId());
    }

    #[PHPUnit\Test]
    public function signMustReturnAHashAccordingWithTheAlgorithm(): void
    {
        $secret = $this->generateSecret();

        $expectedHash = hash_hmac($this->hashAlgorithm(), 'test', $secret, true);
        $signature    = $this->algorithm()->sign('test', InMemory::plainText($secret));

        self::assertTrue(hash_equals($expectedHash, $signature));
    }

    #[PHPUnit\Test]
    public function verifyMustReturnTrueWhenContentWasSignedWithTheSameKey(): void
    {
        $secret = $this->generateSecret();

        $signature = hash_hmac($this->hashAlgorithm(), 'test', $secret, true);

        self::assertTrue($this->algorithm()->verify($signature, 'test', InMemory::plainText($secret)));
    }

    #[PHPUnit\Test]
    public function verifyMustReturnTrueWhenContentWasSignedWithADifferentKey(): void
    {
        $signature = hash_hmac(
            $this->hashAlgorithm(),
            'test',
            $this->generateSecret(),
            true,
        );

        self::assertFalse(
            $this->algorithm()->verify(
                $signature,
                'test',
                InMemory::plainText($this->generateSecret()),
            ),
        );
    }

    #[PHPUnit\Test]
    public function keyMustFulfillMinimumLengthRequirement(): void
    {
        $secret = $this->generateSecret(($this->expectedMinimumBits() / 8) - 1);

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage(
            sprintf(
                'Key provided is shorter than %d bits, only %d bits provided',
                $this->expectedMinimumBits(),
                strlen($secret) * 8,
            ),
        );

        $this->algorithm()->sign('test', InMemory::plainText($secret));
    }

    /** @return non-empty-string */
    private function generateSecret(?int $length = null): string
    {
        $length ??= $this->expectedMinimumBits() / 8;
        assert(is_int($length));
        assert($length > 1);

        return random_bytes($length);
    }
}
