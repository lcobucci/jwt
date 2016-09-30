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
     * @covers \Lcobucci\JWT\ValidationData::__construct
     */
    public function constructorShouldConfigureTheItems()
    {
        $expected = $this->createExpectedData();
        $data = new ValidationData(1);

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setId
     */
    public function setIdShouldChangeTheId()
    {
        $expected = $this->createExpectedData('test');
        $data = new ValidationData(1);
        $data->setId('test');

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setIssuer
     */
    public function setIssuerShouldChangeTheIssuer()
    {
        $expected = $this->createExpectedData(null, null, 'test');
        $data = new ValidationData(1);
        $data->setIssuer('test');

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setIssuer
     */
    public function setIssuerMustAcceptArrayOfValues()
    {
        $expected = $this->createExpectedData(null, null, ['test', 'test2']);
        $data = new ValidationData(1);
        $data->setIssuer(['test', 'test2']);

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setAudience
     */
    public function setAudienceShouldChangeTheAudience()
    {
        $expected = $this->createExpectedData(null, null, null, 'test');
        $data = new ValidationData(1);
        $data->setAudience('test');

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setSubject
     */
    public function setSubjectShouldChangeTheSubject()
    {
        $expected = $this->createExpectedData(null, 'test');
        $data = new ValidationData(1);
        $data->setSubject('test');

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::setCurrentTime
     */
    public function setCurrentTimeShouldChangeTheTimeBasedValues()
    {
        $expected = $this->createExpectedData(null, null, null, null, 2);
        $data = new ValidationData(1);
        $data->setCurrentTime(2);

        self::assertAttributeSame($expected, 'items', $data);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnTrueWhenItemIsNotEmpty()
    {
        $data = new ValidationData(1);

        self::assertTrue($data->has('iat'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsEmpty()
    {
        $data = new ValidationData(1);

        self::assertFalse($data->has('jti'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::has
     */
    public function hasShouldReturnFalseWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        self::assertFalse($data->has('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::get
     */
    public function getShouldReturnTheItemValue()
    {
        $data = new ValidationData(1);

        self::assertEquals(1, $data->get('iat'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\ValidationData::__construct
     *
     * @covers \Lcobucci\JWT\ValidationData::get
     */
    public function getShouldReturnNullWhenItemIsNotDefined()
    {
        $data = new ValidationData(1);

        self::assertNull($data->get('test'));
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
        $id = null,
        $sub = null,
        $iss = null,
        $aud = null,
        $time = 1
    ) {
        if ($iss !== null) {
            $iss = (array) $iss;
            foreach ($iss as $key => $member) {
                $iss[$key] = (string) $member;
            }
        }
        return [
            'jti' => $id !== null ? (string) $id : null,
            'iss' => $iss,
            'aud' => $aud !== null ? (string) $aud : null,
            'sub' => $sub !== null ? (string) $sub : null,
            'iat' => $time,
            'nbf' => $time,
            'exp' => $time
        ];
    }
}
