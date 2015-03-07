<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\EcdsaKeys;
use Lcobucci\JWT\RsaKeys;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class OpenSSLTest extends \PHPUnit_Framework_TestCase
{
    use EcdsaKeys, RsaKeys;

    /**
     * @var OpenSSL|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->signer = $this->getMockForAbstractClass(OpenSSL::class);

        $this->signer->expects($this->any())
                     ->method('getAlgorithmId')
                     ->willReturn('TEST123');

        $this->signer->expects($this->any())
                     ->method('getType')
                     ->willReturn(OPENSSL_KEYTYPE_RSA);

        $this->signer->expects($this->any())
                     ->method('getAlgorithm')
                     ->willReturn(OPENSSL_ALGO_SHA256);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::createHash
     *
     * @expectedException \InvalidArgumentException
     */
    public function createHashShouldRaiseExceptionWhenKeyTypeDontMatch()
    {
        $this->signer->createHash('test', $this->privateEcdsa());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\RsaKeys
     * @uses Lcobucci\JWT\Signer\OpenSSL::validateKey
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::createHash
     */
    public function createHashShouldReturnASignatureForGivenPayload()
    {
        $signature = $this->signer->createHash('test', $this->privateRsa());

        $this->assertInternalType('string', $signature);
        $this->assertNotEmpty($signature);

        return $signature;
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     *
     * @expectedException \InvalidArgumentException
     */
    public function verifyShouldRaiseExceptionWhenKeyTypeDontMatch()
    {
        $this->signer->verify('test', 'test', $this->publicEcdsa());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     */
    public function verifyShouldReturnFalseWhenSignatureIsDifferent()
    {
        $this->assertFalse($this->signer->verify('123', 'test', $this->publicRsa()));
    }

    /**
     * @test
     *
     * @depends createHashShouldReturnASignatureForGivenPayload
     *
     * @uses Lcobucci\JWT\RsaKeys
     * @uses Lcobucci\JWT\Signer\OpenSSL::validateKey
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     */
    public function verifyShouldReturnTrueWhenSignatureMatches($signature)
    {
        $this->assertTrue($this->signer->verify($signature, 'test', $this->publicRsa()));
    }
}
