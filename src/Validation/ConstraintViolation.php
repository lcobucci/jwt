<?php

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Exception;
use RuntimeException;

final class ConstraintViolation extends RuntimeException implements Exception
{
}
