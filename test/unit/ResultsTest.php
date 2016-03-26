<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Exception\InvalidClaimException;
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
        $this->assertEmpty($results->getErrors());
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
        $this->assertTrue($results->isValid());
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
        $results->addError(new InvalidClaimException('iss', 'Value is not valid'));

        $errors = $results->getErrors();
        $this->assertFalse($results->isValid());
        $this->assertArrayHasKey('iss', $results->getErrors());
        $this->assertEquals('Value is not valid', $errors['iss']);
    }
}
