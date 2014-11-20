<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\Claim;

/**
 * Validatable claim that checks if value is greater or equals the given data
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 1.2.0
 */
class GreaterOrEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(array $data)
    {
        if (isset($data[$this->getName()])) {
            return $this->getValue() >= $data[$this->getName()];
        }

        return true;
    }
}
