<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\Exception\InvalidClaimException;
use Lcobucci\JWT\ValidationData;

/**
 * Basic interface for validatable token claims
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
interface Validatable
{
    /**
     * Throws an InvalidClaimException if the given data is invalid to  claim
     *
     * @param ValidationData $data
     *
     * @throws InvalidClaimException
     */
    public function validate(ValidationData $data);
}
