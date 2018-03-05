<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Exception;
use function array_map;
use function implode;

final class InvalidTokenException extends Exception
{
    /**
     * @var ConstraintViolationException[]
     */
    private $violations = [];

    public static function fromViolations(ConstraintViolationException ...$violations): self
    {
        $exception             = new self(self::buildMessage($violations));
        $exception->violations = $violations;

        return $exception;
    }

    /**
     * @param ConstraintViolationException[] $violations
     */
    private static function buildMessage(array $violations): string
    {
        $violations = array_map(
            function (ConstraintViolationException $violation): string {
                return '- ' . $violation->getMessage();
            },
            $violations
        );

        $message  = "The token violates some mandatory constraints, details:\n";
        $message .= implode("\n", $violations);

        return $message;
    }

    /**
     * @return ConstraintViolationException[]
     */
    public function violations(): array
    {
        return $this->violations;
    }
}
