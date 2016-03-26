<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;
use Lcobucci\JWT\Exception\InvalidClaimException;

/**
 * Results returned by validation
 */
class Results implements ResultInterface
{
    /**
     * @var array
     */
    private $errors = [];

    /**
     * @param InvalidClaimException $exception
     */
    public function addError(InvalidClaimException $exception)
    {
        $this->errors[$exception->getClaim()] = $exception->getMessage();
    }

    /**
     * @inheritdoc
     */
    public function isValid(): bool
    {
        return empty($this->errors);
    }

    /**
     * @inheritdoc
     */
    public function getErrors(): array
    {
        return $this->errors;
    }
}
