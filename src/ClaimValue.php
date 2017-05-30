<?php
namespace Lcobucci\JWT;

use InvalidArgumentException;
use JsonSerializable;

final class ClaimValue implements JsonSerializable
{
    private $value;

    public function __construct($value)
    {
        $this->ensureValueIsJsonSerializable($value);

        $this->value = $value;
    }

    public function jsonSerialize()
    {
        return $this->value;
    }

    private function ensureValueIsJsonSerializable($value)
    {
        if (is_scalar($value)) {
            return;
        }

        if (is_object($value) && $value instanceof JsonSerializable) {
            return;
        }

        if (is_array($value)) {
            foreach ($value as $child) {
                $this->ensureValueIsJsonSerializable($child);
            }

            return;
        }

        throw new InvalidArgumentException('Value is not JsonSerializable');
    }
}

