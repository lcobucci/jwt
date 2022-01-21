<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTimeImmutable;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;
use Lcobucci\JWT\Validation\Validator;

final class JwtFacade
{
    /** @param callable(Builder):Builder $customiseBuilder */
    public function issue(
        Signer $signer,
        Key $signingKey,
        callable $customiseBuilder
    ): UnencryptedToken {
        $builder = new Token\Builder(new JoseEncoder(), ChainedFormatter::withUnixTimestampDates());

        $now = new DateTimeImmutable();
        $builder
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+5 minutes'));

        return $customiseBuilder($builder)->getToken($signer, $signingKey);
    }

    public function parse(
        string $unencryptedJwt,
        SignedWith $signedWith,
        ValidAt $validAt,
        Constraint ...$constraints
    ): UnencryptedToken {
        $token = (new Parser(new JoseEncoder()))->parseUnencrypted($unencryptedJwt);

        (new Validator())->assert(
            $token,
            $signedWith,
            $validAt,
            ...$constraints
        );

        return $token;
    }
}
