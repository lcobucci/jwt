<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\Results;

class ResultsTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validation\Results::errors
     */
    public function resultsShouldBeEmptyOnCreation()
    {
        $results = new Results();
        $this->assertEmpty($results->errors());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validation\Results::valid
     */
    public function resultsShouldBeValidOnNoErrors()
    {
        $results = new Results();
        $this->assertTrue($results->valid());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validation\Results::addError
     * @covers Lcobucci\JWT\Validation\Results::valid
     */
    public function resultsShouldBeInvalidOnErrors()
    {
        $results = new Results();
        $results->addError('iss', 'Value is not valid');

        $errors = $results->errors();
        $this->assertFalse($results->valid());
        $this->assertArrayHasKey('iss', $results->errors());
        $this->assertEquals('Value is not valid', $errors['iss']);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validation\Results::addError
     * @covers Lcobucci\JWT\Validation\Results::valid
     */
    public function isExpiredShouldReturnTrueIfExpErrorIsSet()
    {
        $results = new Results();
        $results->addError('exp', 'Expired');

        $errors = $results->errors();
        $this->assertFalse($results->valid());
        $this->assertArrayHasKey('exp', $results->errors());
        $this->assertEquals('Expired', $errors['exp']);
        $this->assertTrue($results->isExpired());
    }
}
