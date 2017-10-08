<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Token\Plain;

abstract class ConstraintTestCase extends \PHPUnit\Framework\TestCase
{
    protected function buildToken(
        array $claims = [],
        array $headers = [],
        Signature $signature = null
    ): Plain {
        return new Plain(
            new DataSet($headers, ''),
            new DataSet($claims, ''),
            $signature ?? Signature::fromEmptyData()
        );
    }
}
