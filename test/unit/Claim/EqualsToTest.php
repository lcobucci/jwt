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
class EqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\EqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDontHaveTheClaim()
    {
        $claim = new EqualsTo('sub', 'test');

        $this->assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\EqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValueIsEqualsToValidationData()
    {
        $claim = new EqualsTo('sub', 'test');

        $data = new ValidationData();
        $data->setSubject('test');

        $this->assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\EqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValueIsNotEqualsToValidationData()
    {
        $claim = new EqualsTo('sub', 'test');

        $data = new ValidationData();
        $data->setSubject('test1');

        $this->assertFalse($claim->validate($data));
    }
}
