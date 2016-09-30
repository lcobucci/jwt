<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 *
 * @since 4.0.0
 */
final class Validator implements \Lcobucci\JWT\Validator
{
    /**
     * {@inheritdoc}
     */
    public function validate(Token $token, array $constraints): Result
    {
        $violations = [];

        foreach ($constraints as $constraint) {
            $violations = $this->verifyConstraint($violations, $constraint, $token);
        }

        return new Result($violations);
    }

    private function verifyConstraint(
        array $violations,
        Constraint $constraint,
        Token $token
    ): array {
        try {
            $constraint->validate($token);
        } catch (ConstraintViolationException $e) {
            $violations[] = $e;
        }

        return $violations;
    }
}
