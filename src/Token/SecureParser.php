<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\SecureParser as SecureParserInterface;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;
use Lcobucci\JWT\Validator;

final class SecureParser implements SecureParserInterface
{
    private Parser $parser;
    private Validator $validator;

    public function __construct(Decoder $decoder, Validator $validator)
    {
        $this->parser    = new Parser($decoder);
        $this->validator = $validator;
    }

    public function parseJwt(
        string $jwt,
        SignedWith $signedWith,
        ValidAt $validAt,
        Constraint ...$constraints
    ): TokenInterface {
        $token = $this->parser->parse($jwt);

        $this->validator->assert(
            $token,
            $signedWith,
            $validAt,
            ...$constraints
        );

        return $token;
    }
}
