<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\ValidationData;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class GreaterOrEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::has
     *
     * @covers Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDontHaveTheClaim()
    {
        $claim = new GreaterOrEqualsTo('iss', 10);

        $this->assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::get
     *
     * @covers Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsGreaterThanValidationData()
    {
        $time = new \DateTime('+1 second');
        $claim = new GreaterOrEqualsTo('iat', $time->getTimestamp());
        $data = new ValidationData(new \DateTime());

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::get
     *
     * @covers Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsEqualsToValidationData()
    {
        $time = new \DateTime();
        $claim = new GreaterOrEqualsTo('iat', $time->getTimestamp());
        $data = new ValidationData($time);

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::get
     *
     * @covers Lcobucci\JWT\Claim\GreaterOrEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValueIsLesserThanValidationData()
    {
        $time = new \DateTime();
        $claim = new GreaterOrEqualsTo('iat', $time->getTimestamp());
        $data = new ValidationData(new \DateTime('+1 second'));

        $this->assertFalse($claim->validate($data));
    }
}
