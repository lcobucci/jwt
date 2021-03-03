<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class SignedWithOneOf implements Constraint
{
    private Signer $signer;

    /**
     * @var Signer\Key[]
     */
    private array $keys;

    /**
     * SignedWith constructor.
     * @param Signer $signer
     * @param Signer\Key[] $keys
     */
    public function __construct(Signer $signer, array $keys)
    {
        $this->signer = $signer;
        $this->keys = $keys;
    }

    public function assert(Token $token): void
    {
        if (! $token instanceof UnencryptedToken) {
            throw new ConstraintViolation('You should pass a plain token');
        }

        if ($token->headers()->get('alg') !== $this->signer->algorithmId()) {
            throw new ConstraintViolation('Token signer mismatch');
        }

        $signatureMatched = false;

        foreach ($this->keys as $key) {
            if ($this->signer->verify($token->signature()->hash(), $token->payload(), $key)) {
                $signatureMatched = true;
                break;
            }
        }

        if (!$signatureMatched) {
            throw new ConstraintViolation('Token signature mismatch. ' . sizeof($this->keys) . " keys were tested");
        }
    }
}
