<?php
namespace Lcobucci\JWT\Validation;

class Results implements ResultsInterface
{
    private $errors = [];

    /**
     * @param string $name
     * @param string $message
     */
    public function addError(string $name, string $message)
    {
        $this->errors[$name] = $message;
    }

    /** @inheritdoc */
    public function valid(): bool
    {
        return empty($this->errors);
    }

    /** @inheritdoc */
    public function errors(): array
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
