<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Keys;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class RsaTest extends \PHPUnit\Framework\TestCase
{
    use Keys;

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::sign
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldReturnAValidOpensslSignature(): void
    {
        $payload = 'testing';

        $signer    = $this->getSigner();
        $signature = $signer->sign($payload, self::$rsaKeys['private']);

        $publicKey = openssl_get_publickey(self::$rsaKeys['public']->getContent());
        self::assertSame(1, openssl_verify($payload, $signature, $publicKey, OPENSSL_ALGO_SHA256));
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::sign
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldRaiseAnExceptionWhenKeyIsInvalid(): void
    {
        $key = <<<KEY
-----BEGIN RSA PRIVATE KEY-----
MGECAQACEQC4MRKSVsq5XnRBrJoX6+rnAgMBAAECECO8SZkgw6Yg66A6SUly/3kC
CQDtPXZtCQWJuwIJAMbBu17GDOrFAggopfhNlFcjkwIIVjb7G+U0/TECCEERyvxP
TWdN
-----END RSA PRIVATE KEY-----
KEY;

        $signer = $this->getSigner();
        $signer->sign('testing', new Key($key));
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::sign
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = $this->getSigner();
        $signer->sign('testing', new Key('blablabla'));
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::sign
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function signShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $signer = $this->getSigner();
        $signer->sign('testing', self::$ecdsaKeys['private']);
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::verify
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldReturnAValidOpensslSignature(): void
    {
        $payload    = 'testing';
        $privateKey = openssl_get_privatekey(self::$rsaKeys['private']->getContent());
        $signature  = '';
        openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA256);

        $signer = $this->getSigner();

        self::assertTrue($signer->verify($signature, $payload, self::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::verify
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = $this->getSigner();
        $signer->verify('testing', 'testing', new Key('blablabla'));
    }

    /**
     * @test
     *
     * @requires extension openssl
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Signer\Rsa::verify
     * @covers \Lcobucci\JWT\Signer\Rsa::validateKey
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function verifyShouldRaiseAnExceptionWhenKeyTypeIsNotRsa(): void
    {
        $signer = $this->getSigner();
        $signer->verify('testing', 'testing', self::$ecdsaKeys['private']);
    }

    private function getSigner(): Rsa
    {
        $signer = $this->getMockForAbstractClass(Rsa::class);

        $signer->method('getAlgorithm')
               ->willReturn(OPENSSL_ALGO_SHA256);

        $signer->method('getAlgorithmId')
               ->willReturn('RS256');

        return $signer;
    }
}
