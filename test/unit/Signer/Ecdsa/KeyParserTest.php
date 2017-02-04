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
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Math\MathAdapterInterface;
use Mdanter\Ecc\Serializer\PrivateKey\PrivateKeySerializerInterface;
use Mdanter\Ecc\Serializer\PublicKey\PublicKeySerializerInterface;
use Lcobucci\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 3.0.4
 */
final class KeyParserTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var GmpMathInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $adapter;

    /**
     * @var PrivateKeySerializerInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $privateKeySerializer;

    /**
     * @var PublicKeySerializerInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    private $publicKeySerializer;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->adapter = $this->createMock(GmpMathInterface::class);
        $this->privateKeySerializer = $this->createMock(PrivateKeySerializerInterface::class);
        $this->publicKeySerializer = $this->createMock(PublicKeySerializerInterface::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     */
    public function constructShouldConfigureDependencies(): void
    {
        $parser = new KeyParser($this->privateKeySerializer, $this->publicKeySerializer);

        self::assertAttributeSame($this->privateKeySerializer, 'privateKeySerializer', $parser);
        self::assertAttributeSame($this->publicKeySerializer, 'publicKeySerializer', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::create
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     */
    public function createShouldReturnAValidInstanceBasedOnTheMathAdapter(): void
    {
        $parser = KeyParser::create($this->adapter);

        self::assertAttributeInstanceOf(
            PrivateKeySerializerInterface::class,
            'privateKeySerializer',
            $parser
        );

        self::assertAttributeInstanceOf(
            PublicKeySerializerInterface::class,
            'publicKeySerializer',
            $parser
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getPrivateKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getKeyContent
     */
    public function getPrivateKeyShouldAskSerializerToParseTheKey(): void
    {
        $privateKey = $this->createMock(PrivateKeyInterface::class);

        $keyContent = 'MHcCAQEEIBGpMoZJ64MMSzuo5JbmXpf9V4qSWdLIl/8RmJLcfn/qoAoGC'
                      . 'CqGSM49AwEHoUQDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpnd0wxa2iF'
                      . 'ruiI2tsEdGFTLTsyU+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==';

        $this->privateKeySerializer->expects($this->once())
                                   ->method('parse')
                                   ->with($keyContent)
                                   ->willReturn($privateKey);

        $parser = new KeyParser($this->privateKeySerializer, $this->publicKeySerializer);
        self::assertSame($privateKey, $parser->getPrivateKey($this->getPrivateKey()));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getPrivateKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getKeyContent
     */
    public function getPrivateKeyShouldRaiseExceptionWhenAWrongKeyWasGiven(): void
    {
        $this->privateKeySerializer->expects($this->never())
                                   ->method('parse');

        $parser = new KeyParser($this->privateKeySerializer, $this->publicKeySerializer);
        $parser->getPrivateKey($this->getPublicKey());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getPublicKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getKeyContent
     */
    public function getPublicKeyShouldAskSerializerToParseTheKey(): void
    {
        $publicKey = $this->createMock(PublicKeyInterface::class);

        $keyContent = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpn'
                      . 'd0wxa2iFruiI2tsEdGFTLTsyU+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==';

        $this->publicKeySerializer->expects($this->once())
                                  ->method('parse')
                                  ->with($keyContent)
                                  ->willReturn($publicKey);

        $parser = new KeyParser($this->privateKeySerializer, $this->publicKeySerializer);
        self::assertSame($publicKey, $parser->getPublicKey($this->getPublicKey()));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @uses \Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     *
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getPublicKey
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser::getKeyContent
     */
    public function getPublicKeyShouldRaiseExceptionWhenAWrongKeyWasGiven(): void
    {
        $this->publicKeySerializer->expects($this->never())
                                  ->method('parse');

        $parser = new KeyParser($this->privateKeySerializer, $this->publicKeySerializer);
        $parser->getPublicKey($this->getPrivateKey());
    }

    /**
     * @return Key
     */
    private function getPrivateKey(): Key
    {
        return new Key(
            "-----BEGIN EC PRIVATE KEY-----\n"
            . "MHcCAQEEIBGpMoZJ64MMSzuo5JbmXpf9V4qSWdLIl/8RmJLcfn/qoAoGCCqGSM49\n"
            . "AwEHoUQDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpnd0wxa2iFruiI2tsEdGFTLTsy\n"
            . "U+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==\n"
            . "-----END EC PRIVATE KEY-----"
        );
    }

    /**
     * @return Key
     */
    private function getPublicKey(): Key
    {
        return new Key(
            "-----BEGIN PUBLIC KEY-----\n"
            . "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7it/EKmcv9bfpcV1fBreLMRXxWpn\n"
            . "d0wxa2iFruiI2tsEdGFTLTsyU+GeRqC7zN0aTnTQajarUylKJ3UWr/r1kg==\n"
            . "-----END PUBLIC KEY-----"
        );
    }
}
