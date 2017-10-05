<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class EccAdapterTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var GmpMathInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $mathInterface;

    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $signer;

    /**
     * @var NistCurve|\PHPUnit_Framework_MockObject_MockObject
     */
    private $nistCurve;

    /**
     * @var SignatureSerializer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $serializer;

    /**
     * @var RandomNumberGeneratorInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $numberGenerator;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->mathInterface   = $this->createMock(GmpMathInterface::class);
        $this->signer          = $this->createMock(Signer::class);
        $this->nistCurve       = $this->createMock(NistCurve::class);
        $this->serializer      = $this->createMock(SignatureSerializer::class);
        $this->numberGenerator = $this->createMock(RandomNumberGeneratorInterface::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     */
    public function constructShouldConfigureDependencies(): void
    {
        $adapter = $this->createAdapter();

        self::assertAttributeSame($this->signer, 'signer', $adapter);
        self::assertAttributeSame($this->nistCurve, 'nistCurve', $adapter);
        self::assertAttributeSame($this->serializer, 'serializer', $adapter);
        self::assertAttributeSame($this->numberGenerator, 'numberGenerator', $adapter);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::create
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     * @uses \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     */
    public function createShouldBuildObjectFromTheMathInterface(): void
    {
        $adapter = EccAdapter::create($this->mathInterface);

        self::assertAttributeInstanceOf(Signer::class, 'signer', $adapter);
        self::assertAttributeInstanceOf(NistCurve::class, 'nistCurve', $adapter);
        self::assertAttributeInstanceOf(SignatureSerializer::class, 'serializer', $adapter);
        self::assertAttributeInstanceOf(RandomNumberGeneratorInterface::class, 'numberGenerator', $adapter);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::createHash
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     */
    public function createHashShouldReturnASerializedSignature(): void
    {
        $key       = $this->createMock(PrivateKeyInterface::class);
        $point     = $this->createMock(GeneratorPoint::class);
        $signature = $this->createMock(SignatureInterface::class);

        $order       = gmp_init(1, 10);
        $randomK     = gmp_init(2, 10);
        $signingHash = gmp_init(3, 10);

        $key->method('getPoint')->willReturn($point);
        $point->method('getOrder')->willReturn($order);

        $this->numberGenerator->expects($this->once())
                              ->method('generate')
                               ->with($order)
                               ->willReturn($randomK);

        $this->signer->expects($this->once())
                         ->method('sign')
                         ->with($key, $signingHash, $randomK)
                         ->willReturn($signature);

        $this->serializer->expects($this->once())
                         ->method('serialize')
                         ->with($signature, 'sha256')
                         ->willReturn('serialized_signature');

        $adapter = $this->createAdapter();

        self::assertEquals(
            'serialized_signature',
            $adapter->createHash($key, $signingHash, 'sha256')
        );
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::verifyHash
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     */
    public function verifyHashShouldReturnTheSignerResult(): void
    {
        $key         = $this->createMock(PublicKeyInterface::class);
        $signature   = $this->createMock(SignatureInterface::class);
        $signingHash = gmp_init(1, 10);

        $this->serializer->expects($this->once())
                         ->method('parse')
                         ->with('test', 'sha256')
                         ->willReturn($signature);

        $this->signer->expects($this->once())
                     ->method('verify')
                     ->with($key, $signature, $signingHash)
                     ->willReturn(true);

        $adapter = $this->createAdapter();

        self::assertTrue(
            $adapter->verifyHash('test', $key, $signingHash, 'sha256')
        );
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::createSigningHash
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::generatorPoint
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     */
    public function createSigningHashShouldRaiseExceptionWhenAlgorithmIsInvalid(): void
    {
        $adapter = $this->createAdapter();
        $adapter->createSigningHash('testing', 'testing');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::createSigningHash
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::generatorPoint
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\EccAdapter::__construct
     */
    public function createSigningHashShouldReturnTheSignerResult(): void
    {
        $signingHash    = gmp_init(1, 10);
        $generatorPoint = $this->createMock(GeneratorPoint::class);

        $this->nistCurve->expects($this->once())
                        ->method('generator256')
                        ->willReturn($generatorPoint);

        $this->signer->expects($this->once())
                     ->method('hashData')
                     ->with($generatorPoint, 'sha256', 'testing')
                     ->willReturn($signingHash);

        $adapter = $this->createAdapter();

        self::assertSame(
            $signingHash,
            $adapter->createSigningHash('testing', 'sha256')
        );
    }

    private function createAdapter(): EccAdapter
    {
        return new EccAdapter(
            $this->signer,
            $this->nistCurve,
            $this->serializer,
            $this->numberGenerator
        );
    }
}
