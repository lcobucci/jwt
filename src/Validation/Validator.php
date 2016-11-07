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
    public function assert(Token $token, Constraint ...$constraints)
    {
        $violations = [];

        foreach ($constraints as $constraint) {
            $this->checkConstraint($constraint, $token, $violations);
        }

        if (!empty($violations)) {
            throw InvalidTokenException::fromViolations(...$violations);
        }
    }

    private function checkConstraint(
        Constraint $constraint,
        Token $token,
        array &$violations
    ) {
        try {
            $constraint->assert($token);
        } catch (ConstraintViolationException $e) {
            $violations[] = $e;
        }
    }

    public function validate(Token $token, Constraint ...$constraints): bool
    {
        try {
            foreach ($constraints as $constraint) {
                $constraint->assert($token);
            }

            return true;
        } catch (ConstraintViolationException $e) {
            return false;
        }
    }
}
