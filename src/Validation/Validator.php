<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Token;

final class Validator implements \Lcobucci\JWT\Validator
{
    /**
     * {@inheritdoc}
     */
    public function assert(Token $token, Constraint ...$constraints): void
    {
        $violations = [];

        foreach ($constraints as $constraint) {
            $this->checkConstraint($constraint, $token, $violations);
        }

        if ($violations) {
            throw InvalidToken::fromViolations(...$violations);
        }
    }

    /**
     * @param ConstraintViolation[] $violations
     */
    private function checkConstraint(
        Constraint $constraint,
        Token $token,
        array &$violations
    ): void {
        try {
            $constraint->assert($token);
        } catch (ConstraintViolation $e) {
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
        } catch (ConstraintViolation $e) {
            return false;
        }
    }
}
