<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Generator;
use Lcobucci\JWT\Claim\Validatable;

/**
 * Class that validates token with defined validationData
 *
 * @author Danny Dörfel <danny.dorfel@gmail.com>
 */
class Validator
{
    private $errors = [];

    /**
     * @param Token $token
     * @param ValidationData $data
     * @return bool
     */
    public function validate(Token $token, ValidationData $data): bool
    {
        $this->errors = [];

        foreach ($this->getValidatableClaims($token) as $claim) {

            if ($data->has($claim->getName()) && !$claim->validate($data)) {
                $this->errors[$claim->getName()] = false;
            }
        }

        return count($this->errors) === 0;
    }

    /**
     * @return array
     */
    public function getErrors(): array
    {
        return $this->errors;
    }

    /**
     * @param Token $token
     * @return Generator
     */
    private function getValidatableClaims(Token $token): Generator
    {
        foreach ($token->getClaims() as $claim) {
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
    }
}
