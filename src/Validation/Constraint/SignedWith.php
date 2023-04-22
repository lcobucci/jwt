<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\SignedWith as SignedWithInterface;

use function is_array;

final class SignedWith implements SignedWithInterface
{
    private readonly Signer\Key|array $keys;

    public function __construct(private readonly Signer $signer, Signer\Key|array $keys)
    {
        if (! is_array($keys)) {
            $keys = [$keys];
        }

        $this->keys = $keys;
    }

    public function assert(Token $token): void
    {
        if (! $token instanceof UnencryptedToken) {
            throw ConstraintViolation::error('You should pass a plain token', $this);
        }

        if ($token->headers()->get('alg') !== $this->signer->algorithmId()) {
            throw ConstraintViolation::error('Token signer mismatch', $this);
        }

        $hash    = $token->signature()->hash();
        $payload = $token->payload();
        $match   = false;
        foreach ($this->keys as $key) {
            if ($this->signer->verify($hash, $payload, $key)) {
                $match = true;
                break;
            }
        }

        if (! $match) {
            throw ConstraintViolation::error('Token signature mismatch', $this);
        }
    }
}
