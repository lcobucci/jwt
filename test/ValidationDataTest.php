<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class ValidationDataTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers Lcobucci\JWT\ValidationData::__construct
     */
    public function constructorShouldConfigureTheItems()
    {
        $data = new ValidationData(1);
        $items = ['jti' => null, 'iss' => null, 'aud' => null, 'sub' => null];
        $items['iat'] = $items['nbf'] = $items['exp'] = 1;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::setId
     */
    public function setIdShouldChangeTheId()
    {
        $data = new ValidationData(1);
        $data->setId(1);

        $items = ['jti' => 1, 'iss' => null, 'aud' => null, 'sub' => null];
        $items['iat'] = $items['nbf'] = $items['exp'] = 1;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::setIssuer
     */
    public function setIssuerShouldChangeTheIssuer()
    {
        $data = new ValidationData(1);
        $data->setIssuer('test');

        $items = ['jti' => null, 'iss' => 'test', 'aud' => null, 'sub' => null];
        $items['iat'] = $items['nbf'] = $items['exp'] = 1;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::setAudience
     */
    public function setAudienceShouldChangeTheAudience()
    {
        $data = new ValidationData(1);
        $data->setAudience('test');

        $items = ['jti' => null, 'iss' => null, 'aud' => 'test', 'sub' => null];
        $items['iat'] = $items['nbf'] = $items['exp'] = 1;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::setSubject
     */
    public function setSubjectShouldChangeTheSubject()
    {
        $data = new ValidationData(1);
        $data->setSubject('test');

        $items = ['jti' => null, 'iss' => null, 'aud' => null, 'sub' => 'test'];
        $items['iat'] = $items['nbf'] = $items['exp'] = 1;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::setCurrentTime
     */
    public function setCurrentTimeShouldChangeTheTimeBasedValues()
    {
        $data = new ValidationData(1);
        $data->setCurrentTime(2);

        $items = ['jti' => null, 'iss' => null, 'aud' => null, 'sub' => null];
        $items['iat'] = $items['nbf'] = $items['exp'] = 2;

        $this->assertAttributeEquals($items, 'items', $data);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnTrueWhenItemIsNotEmpty()
    {
        $data = new ValidationData(1);

        $this->assertTrue($data->has('iat'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsEmpty()
    {
        $data = new ValidationData(1);

        $this->assertFalse($data->has('jti'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        $this->assertFalse($data->has('test'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::get
     */
    public function getShouldReturnTheItemValue()
    {
        $data = new ValidationData(1);

        $this->assertEquals(1, $data->get('iat'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ValidationData::__construct
     *
     * @covers Lcobucci\JWT\ValidationData::get
     */
    public function getShouldReturnNullWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        $this->assertNull($data->get('test'));
    }
}
