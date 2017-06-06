<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\TestFixture\Sha256 as TestSigner;

/**
 * @author Woody Gilk <@shadowhand>
 * @since 3.0.6
 */
class FactoryTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::get
     *
     * @covers Lcobucci\JWT\Signer\Factory::__construct
     * @covers Lcobucci\JWT\Signer\Factory::register
     */
    public function constructCanConfigureRegistry()
    {
        $signer = $this->getMockBuilder('Lcobucci\JWT\Signer\Rsa\Sha256')->getMock();
        $signer->method('getAlgorithmId')->willReturn('RS256');

        $registry = [
            $signer
        ];

        $factory = new Factory($registry);

        $this->assertSame($signer, $factory->get('RS256'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Signer\Factory::get
     * @uses Lcobucci\JWT\Signer\Factory::registerDefaultSigner
     * @uses Lcobucci\JWT\Signer\Factory::register
     *
     * @covers Lcobucci\JWT\Signer\Factory::__construct
     * @covers Lcobucci\JWT\Signer\Factory::getNamespace
     * @covers Lcobucci\JWT\Signer\Factory::getPrefix
     * @covers Lcobucci\JWT\Signer\Factory::getClass
     */
    public function constructCanConfigurePrefixes()
    {
        $prefixes = [
            'TF' => 'TestFixture',
        ];

        $factory = new Factory([], $prefixes);

        $this->assertInstanceOf(TestSigner::class, $factory->get('TF256'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     * @uses Lcobucci\JWT\Signer\Factory::getNamespace
     * @uses Lcobucci\JWT\Signer\Factory::getClass
     * @uses Lcobucci\JWT\Signer\Factory::get
     *
     * @covers Lcobucci\JWT\Signer\Factory::getPrefix
     * @covers Lcobucci\JWT\Signer\Factory::registerDefaultSigner
     */
    public function registerDefaultSignerFailsWithInvalidPrefix()
    {
        $factory = new Factory;

        $factory->get('NO32');
    }

    public function dataDefaultClasses()
    {
        $prefixes = [
            'ES' => 'Ecdsa',
            'HS' => 'Hmac',
            'RS' => 'Rsa',
        ];

        $lengths = [
            256,
            384,
            512,
        ];

        $data = [];
        foreach ($prefixes as $abbr => $prefix) {
            foreach ($lengths as $length) {
                $data[] = [$abbr . $length, "Lcobucci\\JWT\\Signer\\{$prefix}\\Sha{$length}"];
            }
        }

        return $data;
    }

    /**
     * @test
     *
     * @dataProvider dataDefaultClasses
     *
     * @uses Lcobucci\JWT\Signer\Factory::__construct
     * @uses Lcobucci\JWT\Signer\Factory::register
     *
     * @uses Lcobucci\JWT\Signer\Ecdsa\Sha256::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Ecdsa\Sha384::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Ecdsa\Sha512::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Ecdsa::__construct
     * @uses Lcobucci\JWT\Signer\Ecdsa::createSignatureHash
     * @uses Lcobucci\JWT\Signer\Ecdsa\KeyParser::__construct
     * @uses Lcobucci\JWT\Signer\Hmac\Sha256::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Hmac\Sha384::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Hmac\Sha512::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Rsa\Sha256::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Rsa\Sha384::getAlgorithmId
     * @uses Lcobucci\JWT\Signer\Rsa\Sha512::getAlgorithmId
     *
     * @covers Lcobucci\JWT\Signer\Factory::registerDefaultSigner
     * @covers Lcobucci\JWT\Signer\Factory::getNamespace
     * @covers Lcobucci\JWT\Signer\Factory::getPrefix
     * @covers Lcobucci\JWT\Signer\Factory::getClass
     * @covers Lcobucci\JWT\Signer\Factory::get
     */
    public function getShouldReturnDefaultClassNames($algoritm, $class)
    {
        $this->assertInstanceOf($class, (new Factory)->get($algoritm));
    }
}
