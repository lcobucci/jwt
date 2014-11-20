<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 *
 * @coversDefaultClass Lcobucci\JWT\Claim\LesserOrEqualsTo
 */
class LesserOrEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @covers ::validate
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     * @covers Lcobucci\JWT\Claim\Basic::getName
     * @covers Lcobucci\JWT\ValidationData::__construct
     * @covers Lcobucci\JWT\ValidationData::has
     */
    public function validateShouldReturnTrueWhenValidationDontHaveTheClaim()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $this->assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @covers ::validate
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     * @covers Lcobucci\JWT\Claim\Basic::getName
     * @covers Lcobucci\JWT\Claim\Basic::getValue
     * @covers Lcobucci\JWT\ValidationData::__construct
     * @covers Lcobucci\JWT\ValidationData::setIssuer
     * @covers Lcobucci\JWT\ValidationData::has
     * @covers Lcobucci\JWT\ValidationData::get
     */
    public function validateShouldReturnTrueWhenValueIsLesserThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(11);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @covers ::validate
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     * @covers Lcobucci\JWT\Claim\Basic::getName
     * @covers Lcobucci\JWT\Claim\Basic::getValue
     * @covers Lcobucci\JWT\ValidationData::__construct
     * @covers Lcobucci\JWT\ValidationData::setIssuer
     * @covers Lcobucci\JWT\ValidationData::has
     * @covers Lcobucci\JWT\ValidationData::get
     */
    public function validateShouldReturnTrueWhenValueIsEqualsToValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @covers ::validate
     * @covers Lcobucci\JWT\Claim\Basic::__construct
     * @covers Lcobucci\JWT\Claim\Basic::getName
     * @covers Lcobucci\JWT\Claim\Basic::getValue
     * @covers Lcobucci\JWT\ValidationData::__construct
     * @covers Lcobucci\JWT\ValidationData::setIssuer
     * @covers Lcobucci\JWT\ValidationData::has
     * @covers Lcobucci\JWT\ValidationData::get
     */
    public function validateShouldReturnFalseWhenValueIsGreaterThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iss', 11);

        $data = new ValidationData();
        $data->setIssuer(10);

        $this->assertFalse($claim->validate($data));
    }
}
