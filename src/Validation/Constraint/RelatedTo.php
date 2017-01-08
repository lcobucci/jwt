<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolationException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class RelatedTo implements Constraint
{
    /**
     * @var string
     */
    private $subject;

    public function __construct(string $subject)
    {
        $this->subject = $subject;
    }

    /**
     * {@inheritdoc}
     */
    public function assert(Token $token): void
    {
        if (!$token->isRelatedTo($this->subject)) {
            throw new ConstraintViolationException(
                'The token is not related to the expected subject'
            );
        }
    }
}
