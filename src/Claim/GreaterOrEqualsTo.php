<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Claim;

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Exception\RangeException;
use Lcobucci\JWT\ValidationData;

/**
 * Validatable claim that checks if value is greater or equals the given data
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class GreaterOrEqualsTo extends Basic implements Claim, Validatable
{
    /**
     * {@inheritdoc}
     */
    public function validate(ValidationData $data)
    {
        $name = $this->getName();
        if ($data->has($name) && ($this->getValue() < $data->get($name))) {
            throw new RangeException($name, "The claim value should be greater than the validation value");
        }
    }
}
