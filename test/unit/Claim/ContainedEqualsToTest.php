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
class ContainedEqualsToTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\ContainedEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenValidationDoesntHaveTheClaim()
    {
        $claim = new ContainedEqualsTo('iss', 'test');

        self::assertTrue($claim->validate(new ValidationData()));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\ContainedEqualsTo::validate
     */
    public function validateShouldReturnTrueWhenClaimValueIsEqualToAtLeastOneItemInValidationData()
    {
        $claim = new ContainedEqualsTo('iss', 'test');

        $data = new ValidationData();
        $data->setIssuer(['test', 'test2']);

        self::assertTrue($claim->validate($data));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Claim\Basic
     * @uses \Lcobucci\JWT\ValidationData
     *
     * @covers \Lcobucci\JWT\Claim\ContainedEqualsTo::validate
     */
    public function validateShouldReturnFalseWhenClaimValueIsNotEqualToAtLeastOneItemInValidationData()
    {
        $claim = new ContainedEqualsTo('iss', 'test');

        $data = new ValidationData();
        $data->setIssuer(['test2', 'test3']);

        self::assertFalse($claim->validate($data));
    }
}
