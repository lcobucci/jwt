<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolationException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class SignedWith implements Constraint
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Signer\Key
     */
    private $key;

    public function __construct(Signer $signer, Signer\Key $key)
    {
        $this->signer = $signer;
        $this->key = $key;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token): void
    {
        if (!$token instanceof Token\Plain) {
            throw new ConstraintViolationException('You should pass a plain token');
        }

        $signature = $token->signature();

        if (!$signature) {
            throw new ConstraintViolationException('The token is not signed');
        }

        if ($token->headers()->get('alg') !== $this->signer->getAlgorithmId()) {
            throw new ConstraintViolationException('Token signer mismatch');
        }

        if (!$this->signer->verify($signature->hash(), $token->payload(), $this->key)) {
            throw new ConstraintViolationException('Token signature mismatch');
        }
    }
}
