<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Keychain;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class KeychainTest extends \PHPUnit_Framework_TestCase
{
    use Keys;

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPrivateKey
     *
     * @expectedException \InvalidArgumentException
     */
    public function getPrivateKeyShouldRaiseExceptionWhenInvalidKeyIsInformed()
    {
        $keychain = new Keychain();
        $keychain->getPrivateKey('blablabla');
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPrivateKey
     */
    public function getPrivateKeyShouldReturnAValidResource()
    {
        $keychain = new Keychain();

        $privateKey = $keychain->getPrivateKey(file_get_contents(__DIR__ . '/rsa/private.key'));

        $this->assertInternalType('resource', $privateKey);
        $this->assertEquals(openssl_pkey_get_details($privateKey), openssl_pkey_get_details(static::$rsaKeys['private']));
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPrivateKey
     */
    public function getPrivateKeyShouldBeAbleToUseAPassphrase()
    {
        $keychain = new Keychain();

        $privateKey = $keychain->getPrivateKey(file_get_contents(__DIR__ . '/rsa/encrypted-private.key'), 'testing');

        $this->assertInternalType('resource', $privateKey);

        $this->assertEquals(
            openssl_pkey_get_details($privateKey),
            openssl_pkey_get_details(static::$rsaKeys['encrypted-private'])
        );
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPublicKey
     *
     * @expectedException \InvalidArgumentException
     */
    public function getPublicKeyShouldRaiseExceptionWhenInvalidCertificateIsInformed()
    {
        $keychain = new Keychain();
        $keychain->getPublicKey('blablabla');
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPublicKey
     */
    public function getPublicKeyShouldReturnAValidResource()
    {
        $keychain = new Keychain();

        $publicKey = $keychain->getPublicKey(file_get_contents(__DIR__ . '/rsa/public.key'));

        $this->assertInternalType('resource', $publicKey);
        $this->assertEquals(openssl_pkey_get_details($publicKey), openssl_pkey_get_details(static::$rsaKeys['public']));
    }
}
