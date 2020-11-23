<?php

namespace Lcobucci\JWT\Validation;

use Lcobucci\JWT\Exception;
use RuntimeException;

final class NoConstraintsGiven extends RuntimeException implements Exception
{
}
