<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Generator;
use Lcobucci\JWT\Claim\Validatable;
use Lcobucci\JWT\Exception\InvalidClaimException;
use Lcobucci\JWT\Validation\Results;
use Lcobucci\JWT\Validation\ResultsInterface;

/**
 * Class that validates token with defined validationData
 *
 * @author Danny Dörfel <danny.dorfel@gmail.com>
 */
class Validator implements ValidatorInterface
{
    /**
     * @var ValidationData
     */
    private $data;

    public function __construct(ValidationData $data)
    {
        $this->data = $data;
    }

    /**
     * @param Token $token
     * @return ResultsInterface
     */
    public function validate(Token $token): ResultsInterface
    {
        $results = new Results();

        foreach ($this->getValidatableClaims($token) as $claim) {
            try {
                $claim->validate($this->data);
            } catch (InvalidClaimException $exception) {
                $results->addError($claim->getName(), $exception->getMessage());
            }
        }

        return $results;
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
