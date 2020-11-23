<?php

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signature;
use PHPUnit\Framework\TestCase;

abstract class ConstraintTestCase extends TestCase
{
    /**
     * @param mixed[] $claims
     * @param mixed[] $headers
     *
     * @return Token
     */
    protected function buildToken(
        array $claims = [],
        array $headers = [],
        Signature $signature = null
    ) {
        return new Token(
            $headers,
            $claims,
            $signature,
            ['', '', '']
        );
    }
}
