<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\ResultsInterface;

interface ValidatorInterface
{
    /**
     * @param Token $token
     * @return ResultsInterface
     */
    public function validate(Token $token): ResultsInterface;
}
