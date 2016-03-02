<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\ValidationData;

/**
 * Validatable claim that checks if claim value is strictly equal to an item in the given validation data set.
 *
 * @author Matthew John Marshall <matthew.marshall96@yahoo.co.uk>
 * @since 4.0.0
 */
class ContainedEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data) : bool
    {
        if ($data->has($this->getName())) {
            return in_array($this->getValue(), $data->get($this->getName()));
        }

        return true;
    }
}
