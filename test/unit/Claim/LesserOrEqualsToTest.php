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
class LesserOrEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::has
     *
     * @covers Lcobucci\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnWhenValidationDontHaveTheClaim()
    {
        $claim = new LesserOrEqualsTo('iss', 10);

        $this->assertNull($claim->validate(new ValidationData()));
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
     * @covers Lcobucci\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnWhenValueIsLesserThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iat', 10);
        $data = new ValidationData(11);

        $this->assertNull($claim->validate($data));
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
     * @covers Lcobucci\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldReturnWhenValueIsEqualsToValidationData()
    {
        $claim = new LesserOrEqualsTo('iat', 10);
        $data = new ValidationData(10);

        $this->assertNull($claim->validate($data));
    }

    /**
     * @test
     * @expectedException \Lcobucci\JWT\Exception\InvalidClaimException
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\Claim\Basic::getValue
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::setIssuer
     * @uses Lcobucci\JWT\ValidationData::has
     * @uses Lcobucci\JWT\ValidationData::get
     *
     * @covers Lcobucci\JWT\Claim\LesserOrEqualsTo::validate
     */
    public function validateShouldRaiseExceptionWhenValueIsGreaterThanValidationData()
    {
        $claim = new LesserOrEqualsTo('iat', 11);
        $data = new ValidationData(10);

        $this->assertFalse($claim->validate($data));
    }
}
