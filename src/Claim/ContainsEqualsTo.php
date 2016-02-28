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
 * Validatable claim that checks if the claim value set contains a value strictly equal to the validation item value.
 *
 * @author Matthew John Marshall <matthew.marshall96@yahoo.co.uk>
 * @since 4.x.x
 */
class ContainsEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data): bool
    {
        if ($data->has($this->getName())) {
            foreach ($data->get($this->getName()) as $claimValue) {
                if ($this->getValue() === $claimValue) {
                    return true;
                }
            }
            return false;
        }
        return true;
    }
}
