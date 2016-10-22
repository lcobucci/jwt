<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use BadMethodCallException;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Plain;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
interface Builder
{
    /**
     * Appends a new audience
     */
    public function canOnlyBeUsedBy(string $audience, bool $addHeader = false): Builder;

    /**
     * Configures the expiration time
     */
    public function expiresAt(int $expiration, bool $addHeader = false): Builder;

    /**
     * Configures the token id
     */
    public function identifiedBy(string $id, bool $addHeader = false): Builder;

    /**
     * Configures the time that the token was issued
     */
    public function issuedAt(int $issuedAt, bool $addHeader = false): Builder;

    /**
     * Configures the issuer
     */
    public function issuedBy(string $issuer, bool $addHeader = false): Builder;

    /**
     * Configures the time before which the token cannot be accepted
     */
    public function canOnlyBeUsedAfter(int $notBefore, bool $addHeader = false): Builder;

    /**
     * Configures the subject
     */
    public function relatedTo(string $subject, bool $addHeader = false): Builder;

    /**
     * Configures a header item
     *
     * @throws BadMethodCallException When data has been already signed
     */
    public function withHeader(string $name, $value): Builder;

    /**
     * Configures a claim item
     *
     * @throws BadMethodCallException When data has been already signed
     */
    public function with(string $name, $value): Builder;

    /**
     * Signs the data
     */
    public function sign(Signer $signer, Key $key): Builder;

    /**
     * Removes the signature from the builder
     */
    public function unsign(): Builder;

    /**
     * Returns the resultant token
     */
    public function getToken(): Plain;
}
