<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\TestCase;

abstract class ConstraintTestCase extends TestCase
{
    /**
     * @param mixed[] $claims
     * @param mixed[] $headers
     */
    protected function buildToken(
        array $claims = [],
        array $headers = [],
        ?Signature $signature = null
    ): Plain {
        return new Plain(
            new DataSet($headers, ''),
            new DataSet($claims, ''),
            $signature ?? Signature::fromEmptyData()
        );
    }
}
