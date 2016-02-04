<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

/**
 * @author Danny Dörfel <danny.dorfel@gmail.com>
 */
class ValidatorTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validator::validate
     */
    public function validateShouldValidateTheData()
    {
        $token = $this->getToken(['iss' => 'test']);
        $data = $this->getValidationData();

        $validator = new Validator();
        $this->assertTrue($validator->validate($token, $data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validator::validate
     */
    public function validatorShouldReturnFalseOnErrors()
    {
        $token = $this->getToken(['iss' => 'tester']);
        $data = $this->getValidationData();

        $validator = new Validator();
        $this->assertFalse($validator->validate($token, $data));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Validator::__construct
     *
     * @covers Lcobucci\JWT\Validator::getErrors
     */
    public function validatorShouldHaveErrors()
    {
        $token = $this->getToken(['iss' => 'tester']);
        $data = $this->getValidationData();

        $validator = new Validator();
        $this->assertFalse($validator->validate($token, $data));
        $this->assertEquals(['iss' => false], $validator->getErrors());
    }

    public function getValidationData()
    {
        $data = new ValidationData(1);
        $data->setIssuer('test');

        return $data;
    }

    public function getToken($claims)
    {
        $builder = new Builder();

        foreach ($claims as $claim => $value) {
            $builder->set($claim, $value);
        }

        return $builder->getToken();
    }
}
