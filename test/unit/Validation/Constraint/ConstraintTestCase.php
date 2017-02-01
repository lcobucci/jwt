<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token as TokenInterface;

abstract class ConstraintTestCase extends \PHPUnit_Framework_TestCase
{
    protected function buildToken(
        array $claims = [],
        array $headers = [],
        Signature $signature = null
    ): TokenInterface {
        $headers = new DataSet($headers, '');
        $claims = new DataSet($claims, '');
        $signature = $signature ?? new Signature('', '');

        return new Plain($headers, $claims, $signature);
    }
}
