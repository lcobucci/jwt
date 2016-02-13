<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

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
     * @param string $name
     * @param string $message
     */
    public function addError(string $name, string $message)
    {
        $this->errors[$name] = $message;
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

    /**
     * @return bool
     */
    public function isExpired(): bool
    {
        return isset($this->errors['exp']);
    }
}
