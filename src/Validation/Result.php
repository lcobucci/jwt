<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
final class Result
{
    /**
     * @var ConstraintViolationException[]
     */
    private $violations;

    /**
     * @param array $violations
     */
    public function __construct(array $violations)
    {
        $this->violations = $violations;
    }

    public function hasErrors(): bool
    {
        return !$this->violations;
    }

    public function getErrors():array
    {
        return $this->violations;
    }
}
