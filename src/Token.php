<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTimeInterface;
use Lcobucci\JWT\Token\DataSet;

/**
 * Defines the basic structure of plain and encoded tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
interface Token
{
    /**
     * Returns the token headers
     */
    public function headers(): DataSet;

    /**
     * Returns if the token is allowed to be used by the audience
     */
    public function isAllowedTo(string $audience): bool;

    /**
     * Returns if the token has the given id
     */
    public function isIdentifiedBy(string $id): bool;

    /**
     * Returns if the token has the given subject
     */
    public function isRelatedTo(string $subject): bool;

    /**
     * Returns if the token was issued by any of given issuers
     */
    public function hasBeenIssuedBy(string ...$issuers): bool;

    /**
     * Returns if the token was issued before of given time
     */
    public function hasBeenIssuedBefore(DateTimeInterface $now): bool;

    /**
     * Returns if the token minimum time is before than given time
     */
    public function isMinimumTimeBefore(DateTimeInterface $now): bool;

    /**
     * Returns if the token is expired
     */
    public function isExpired(DateTimeInterface $now): bool;

    /**
     * Returns an encoded representation of the token
     */
    public function __toString(): string;
}
