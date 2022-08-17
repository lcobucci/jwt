<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Exception;
use RuntimeException;

use function get_class;

final class ConstraintViolation extends RuntimeException implements Exception
{
    /**
     * @readonly
     * @var class-string<Constraint>|null
     */
    public ?string $constraint = null;

    public static function error(string $message, Constraint $constraint): self
    {
        $exception             = new self($message);
        $exception->constraint = get_class($constraint);

        return $exception;
    }
}
