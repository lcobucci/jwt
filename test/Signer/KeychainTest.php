<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\RsaKeys;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class KeychainTest extends \PHPUnit_Framework_TestCase
{
    use RsaKeys;

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
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPrivateKey
     */
    public function getPrivateKeyShouldReturnAValidResource()
    {
        $keychain = new Keychain();

        $privateKey = $keychain->getPrivateKey($this->privateRsaContent());

        $this->assertInternalType('resource', $privateKey);
        $this->assertEquals(openssl_pkey_get_details($privateKey), openssl_pkey_get_details($this->privateRsa()));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPrivateKey
     */
    public function getPrivateKeyShouldBeAbleToUseAPassphrase()
    {
        $keychain = new Keychain();

        $privateKey = $keychain->getPrivateKey($this->encryptedPrivateRsaContent(), 'testing');

        $this->assertInternalType('resource', $privateKey);

        $this->assertEquals(
            openssl_pkey_get_details($privateKey),
            openssl_pkey_get_details($this->encryptedPrivateRsa())
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
     * @uses Lcobucci\JWT\RsaKeys
     *
     * @covers Lcobucci\JWT\Signer\Keychain::getPublicKey
     */
    public function getPublicKeyShouldReturnAValidResource()
    {
        $keychain = new Keychain();

        $publicKey = $keychain->getPublicKey($this->publicRsaContent());

        $this->assertInternalType('resource', $publicKey);
        $this->assertEquals(openssl_pkey_get_details($publicKey), openssl_pkey_get_details($this->publicRsa()));
    }
}
