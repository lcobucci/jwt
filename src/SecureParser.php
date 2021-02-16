<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;

interface SecureParser
{
    /**
     * Parses the JWT and returns a valid token
     *
     * @throws CannotDecodeContent          When something goes wrong while decoding.
     * @throws InvalidTokenStructure        When token string structure is invalid.
     * @throws UnsupportedHeaderFound       When parsed token has an unsupported header.
     * @throws RequiredConstraintsViolated  When parsed token violates required constraints.
     */
    public function parse(string $jwt, SignedWith $signedWith, ValidAt $validAt, Constraint ...$constraints): Token;
}
