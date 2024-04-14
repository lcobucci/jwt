<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer;

use Lcobucci\JWT\Signer\Blake2b;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function hash_equals;

#[PHPUnit\CoversClass(Blake2b::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(InvalidKeyProvided::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
final class Blake2bTest extends TestCase
{
    private const KEY_ONE                    = 'GOu4rLyVCBxmxP+sbniU68ojAja5PkRdvv7vNvBCqDQ=';
    private const KEY_TWO                    = 'Pu7gywseH+R5HLIWnMll4rEg1ltjUPq/P9WwEzAsAb8=';
    private const CONTENTS                   = 'test';
    private const EXPECTED_HASH_WITH_KEY_ONE = '/TG5kmkav/YGl3I9uQiv4cm1VN6Q0zPCom4G7+p74JU=';

    private const SHORT_KEY = 'PIBQuM5PopdMxtmTWmyvNA==';

    private InMemory $keyOne;
    private InMemory $keyTwo;
    /** @var non-empty-string */
    private string $expectedHashWithKeyOne;

    #[PHPUnit\Before]
    public function initializeKey(): void
    {
        $this->keyOne = InMemory::base64Encoded(self::KEY_ONE);
        $this->keyTwo = InMemory::base64Encoded(self::KEY_TWO);

        $this->expectedHashWithKeyOne = SodiumBase64Polyfill::base642bin(
            self::EXPECTED_HASH_WITH_KEY_ONE,
            SodiumBase64Polyfill::SODIUM_BASE64_VARIANT_ORIGINAL,
        );
    }

    #[PHPUnit\Test]
    public function algorithmIdMustBeCorrect(): void
    {
        $signer = new Blake2b();

        self::assertSame('BLAKE2B', $signer->algorithmId());
    }

    #[PHPUnit\Test]
    public function generatedSignatureMustBeSuccessfullyVerified(): void
    {
        $signer = new Blake2b();

        self::assertTrue(hash_equals($this->expectedHashWithKeyOne, $signer->sign(self::CONTENTS, $this->keyOne)));
        self::assertTrue($signer->verify($this->expectedHashWithKeyOne, self::CONTENTS, $this->keyOne));
    }

    #[PHPUnit\Test]
    public function signShouldRejectShortKeys(): void
    {
        $signer = new Blake2b();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionMessage('Key provided is shorter than 256 bits, only 128 bits provided');

        $signer->sign(self::CONTENTS, InMemory::base64Encoded(self::SHORT_KEY));
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnFalseWhenExpectedHashWasNotCreatedWithSameInformation(): void
    {
        $signer = new Blake2b();

        self::assertFalse(hash_equals($this->expectedHashWithKeyOne, $signer->sign(self::CONTENTS, $this->keyTwo)));
        self::assertFalse($signer->verify($this->expectedHashWithKeyOne, self::CONTENTS, $this->keyTwo));
    }
}
