<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validator;

final class ValidateDuringParsing implements ParserInterface
{
    private ParserInterface $decorated;
    private Validator $validator;
    private SignedWith $signatureVerification;

    /** @var LooseValidAt|StrictValidAt */
    private LooseValidAt|StrictValidAt $timeVerification;

    /** @var Constraint[] */
    private array $extraConstraints;

    public function __construct(
        ParserInterface $decorated,
        Validator $validator,
        SignedWith $signatureVerification,
        LooseValidAt | StrictValidAt $timeVerification,
        Constraint ...$extraConstraints
    ) {
        $this->decorated             = $decorated;
        $this->validator             = $validator;
        $this->signatureVerification = $signatureVerification;
        $this->timeVerification      = $timeVerification;
        $this->extraConstraints      = $extraConstraints;
    }

    public function parse(string $jwt): Token
    {
        $token = $this->decorated->parse($jwt);

        $constraints = [
            $this->timeVerification,
            ...$this->extraConstraints,
            $this->signatureVerification,
        ];

        if (! $this->validator->validate($token, ...$constraints)) {
            throw new InvalidTokenStructure('Token claims failed validation process');
        }

        return $token;
    }
}
