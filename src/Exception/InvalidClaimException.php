<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Exception;

use Exception;

/**
 * Invalid claim exception to be thrown on claim validation
 */
class InvalidClaimException extends \InvalidArgumentException
{
    private $claim;

    public function __construct(string $claim, $message = "", $code = 0, Exception $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->claim = $claim;
    }

    /**
     * @return string
     */
    public function getClaim()
    {
        return $this->claim;
    }
}
