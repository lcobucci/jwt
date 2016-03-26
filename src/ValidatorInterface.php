<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Validation\ResultInterface;

/**
 * Basic interface describing the validator api
 */
interface ValidatorInterface
{
    /**
     * @param Token $token
     * @return ResultInterface
     */
    public function validate(Token $token): ResultInterface;
}
