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
 * @author Matthew John Marshall <matthew.marshall96@yahoo.co.uk>
 * @since 4.0.0
 */
class ContainsEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\ValidationData
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
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\ValidationData
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
     * @uses Lcobucci\JWT\Claim\Basic
     * @uses Lcobucci\JWT\ValidationData
     *
     * @covers Lcobucci\JWT\Claim\ContainsEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenValidationDataValueIsNotContained()
    {
        $claim = new ContainsEqualsTo('aud', ['test', 'test2']);

        $data = new ValidationData();
        $data->setAudience('test3');

        $this->assertFalse($claim->validate($data));
    }
}
