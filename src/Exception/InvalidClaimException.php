<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Exception;

/**
 * Invalid claim exception to be thrown on claim validation
 */
class InvalidClaimException extends \InvalidArgumentException
{

}
