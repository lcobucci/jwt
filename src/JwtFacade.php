<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token as TokenInterface;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;
use Lcobucci\JWT\Validation\Validator;

final class JwtFacade
{
    public function parse(
        string $jwt,
        SignedWith $signedWith,
        ValidAt $validAt,
        Constraint ...$constraints
    ): TokenInterface {
        $token = (new Parser(new JoseEncoder()))->parse($jwt);

        (new Validator())->assert(
            $token,
            $signedWith,
            $validAt,
            ...$constraints
        );

        return $token;
    }
}
