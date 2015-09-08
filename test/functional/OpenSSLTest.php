<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\OpenSSL;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class OpenSSLTest extends \PHPUnit_Framework_TestCase
{
    use Keys;

    /**
     * @var OpenSSL|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signer;

    /**
     * @before
     */
    protected function createSigner()
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
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::createHash
     *
     * @expectedException \InvalidArgumentException
     */
    public function createHashShouldRaiseExceptionWhenKeyTypeDontMatch()
    {
        $this->signer->createHash('test', static::$ecdsaKeys['private']);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\OpenSSL::validateKey
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::createHash
     */
    public function createHashShouldReturnASignatureForGivenPayload()
    {
        $signature = $this->signer->createHash('test', static::$rsaKeys['private']);

        $this->assertInternalType('string', $signature);
        $this->assertNotEmpty($signature);

        return $signature;
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     *
     * @expectedException \InvalidArgumentException
     */
    public function verifyShouldRaiseExceptionWhenKeyTypeDontMatch()
    {
        $this->signer->verify('test', 'test', static::$ecdsaKeys['public1']);
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::validateKey
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     */
    public function verifyShouldReturnFalseWhenSignatureIsDifferent()
    {
        $this->assertFalse($this->signer->verify('123', 'test', static::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @depends createHashShouldReturnASignatureForGivenPayload
     *
     * @uses Lcobucci\JWT\Signer\OpenSSL::validateKey
     *
     * @covers Lcobucci\JWT\Signer\OpenSSL::verify
     */
    public function verifyShouldReturnTrueWhenSignatureMatches($signature)
    {
        $this->assertTrue($this->signer->verify($signature, 'test', static::$rsaKeys['public']));
    }
}
