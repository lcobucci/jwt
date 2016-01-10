<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

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
        $time = new \DateTime();
        $expected = $this->createExpectedData();
        $data = new ValidationData($time->setTimestamp(1));

        $this->assertAttributeSame($expected, 'items', $data);
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
        $time = new \DateTime();
        $expected = $this->createExpectedData('test');
        $data = new ValidationData($time->setTimestamp(1));
        $data->setId('test');

        $this->assertAttributeSame($expected, 'items', $data);
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
        $time = new \DateTime();
        $expected = $this->createExpectedData(null, null, 'test');
        $data = new ValidationData($time->setTimestamp(1));
        $data->setIssuer('test');

        $this->assertAttributeSame($expected, 'items', $data);
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
        $time = new \DateTime();
        $expected = $this->createExpectedData(null, null, null, 'test');
        $data = new ValidationData($time->setTimestamp(1));
        $data->setAudience('test');

        $this->assertAttributeSame($expected, 'items', $data);
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
        $time = new \DateTime();
        $expected = $this->createExpectedData(null, 'test');
        $data = new ValidationData($time->setTimestamp(1));
        $data->setSubject('test');

        $this->assertAttributeSame($expected, 'items', $data);
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
        $time = new \DateTime();
        $expected = $this->createExpectedData(null, null, null, null, 2);
        $data = new ValidationData($time->setTimestamp(1));
        $data->setCurrentTime($time->setTimestamp(2));

        $this->assertAttributeSame($expected, 'items', $data);
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
        $data = new ValidationData(new \DateTime());

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
        $data = new ValidationData(new \DateTime());

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
        $data = new ValidationData(new \DateTime());

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
        $time = new \DateTime();
        $data = new ValidationData($time->setTimestamp(1));

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
        $data = new ValidationData(new \DateTime());

        $this->assertNull($data->get('test'));
    }

    /**
     * @param string $id
     * @param string $sub
     * @param string $iss
     * @param string $aud
     * @param int $time
     *
     * @return array
     */
    private function createExpectedData(
        string $id = null,
        string $sub = null,
        string $iss = null,
        string $aud = null,
        int $time = 1
    ): array {
        return [
            'jti' => $id,
            'iss' => $iss,
            'aud' => $aud,
            'sub' => $sub,
            'iat' => $time,
            'nbf' => $time,
            'exp' => $time
        ];
    }
}
