<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Math\GmpMath;
use Mdanter\Ecc\Math\GmpMathInterface;
use PHPUnit\Framework\TestCase;
use function gmp_init;
use function pack;
use function str_repeat;

final class SignatureSerializerTest extends TestCase
{
    /**
     * @var GmpMathInterface
     */
    private $mathInterface;

    /**
     * @var Signature
     */
    private $signature;

    /**
     * @var mixed[]
     */
    private $signatureData;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->mathInterface = new GmpMath();

        $points = ['R' => 1, 'S' => 2];

        $this->signature = new Signature(
            gmp_init($points['R'], 10),
            gmp_init($points['S'], 10)
        );

        $this->signatureData = [
            'sha256' => pack(
                'H*',
                str_repeat('0', 63) . $points['R'] . str_repeat('0', 63) . $points['S']
            ),
            'sha384' => pack(
                'H*',
                str_repeat('0', 95) . $points['R'] . str_repeat('0', 95) . $points['S']
            ),
            'sha512' => pack(
                'H*',
                str_repeat('0', 131) . $points['R'] . str_repeat('0', 131) . $points['S']
            ),
        ];
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::__construct
     */
    public function constructShouldConfigureDependencies(): void
    {
        $serializer = new SignatureSerializer($this->mathInterface);

        self::assertAttributeSame($this->mathInterface, 'mathInterface', $serializer);
    }

    /**
     * @test
     *
     * @dataProvider algorithms
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::serialize
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::addPadding
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::__construct
     */
    public function serializeShouldReturnReturnABinarySignatureBasedOnSignaturePoints(string $algorithm): void
    {
        $serializer = new SignatureSerializer($this->mathInterface);

        self::assertEquals(
            $this->signatureData[$algorithm],
            $serializer->serialize($this->signature, $algorithm)
        );
    }

    /**
     * @test
     *
     * @dataProvider algorithms
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::parse
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer::__construct
     */
    public function parseShouldExtractASignatureBasedOnTheHash(string $algorithm): void
    {
        $serializer = new SignatureSerializer($this->mathInterface);

        self::assertEquals(
            $this->signature,
            $serializer->parse($this->signatureData[$algorithm], $algorithm)
        );
    }

    /**
     * @return string[][]
     */
    public function algorithms(): array
    {
        return [
            ['sha256'],
            ['sha384'],
            ['sha512'],
        ];
    }
}
