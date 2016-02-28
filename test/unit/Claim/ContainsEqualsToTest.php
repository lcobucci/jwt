<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\ValidationData;

/**
 * @author Matthew John Marshall <matthew.marshall96@yahoo.co.uk>
 * @since 3.2.0
 */
class ContainsEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic::__construct
     * @uses Lcobucci\JWT\Claim\Basic::getName
     * @uses Lcobucci\JWT\ValidationData::__construct
     * @uses Lcobucci\JWT\ValidationData::has
     *
     * @covers Lcobucci\JWT\Claim\ContainsEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDoesntHaveTheClaim()
    {
        $claim = new ContainsEqualsTo('aud', ['test', 'test2']);

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
     * @covers Lcobucci\JWT\Claim\ContainsEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDataValueIsContained()
    {
        $claim = new ContainsEqualsTo('aud', ['test', 'test2']);

        $data = new ValidationData();
        $data->setAudience('test');

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
     * @covers Lcobucci\JWT\Claim\ContainsEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValidationDataValueIsNotContained()
    {
        $claim = new EqualsTo('aud', ['test', 'test2']);

        $data = new ValidationData();
        $data->setAudience('test3');

        $this->assertFalse($claim->validate($data));
    }
}
