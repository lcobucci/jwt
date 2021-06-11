<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\TimedRequiringBuilder;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;
use Lcobucci\JWT\Validation\Validator;

use function assert;

final class JwtFacade
{
    public function getBuilder(): Builder
    {
        return new TimedRequiringBuilder(new Token\Builder(
            new JoseEncoder(),
            ChainedFormatter::withUnixTimestampDates()
        ));
    }

    public function parse(
        string $jwt,
        SignedWith $signedWith,
        ValidAt $validAt,
        Constraint ...$constraints
    ): UnencryptedToken {
        $token = (new Parser(new JoseEncoder()))->parse($jwt);

        assert($token instanceof UnencryptedToken);

        (new Validator())->assert(
            $token,
            $signedWith,
            $validAt,
            ...$constraints
        );

        return $token;
    }
}
