<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class RsaTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers Lcobucci\JWT\Signer\Rsa::getType
     */
    public function getTypeMustBeCorrect()
    {
        $signer = $this->getMockForAbstractClass(Rsa::class);

        $this->assertEquals(OPENSSL_KEYTYPE_RSA, $signer->getType());
    }
}
