<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use DateTime;
use DateTimeInterface;
use Lcobucci\JWT\Signer\Key;
use OutOfBoundsException;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Token
{
    /**
     * The token headers
     *
     * @var array
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var array
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature
     */
    private $signature;

    /**
     * The encoded data
     *
     * @var array
     */
    private $payload;

    /**
     * Initializes the object
     *
     * @param array $headers
     * @param array $claims
     * @param Signature|null $signature
     * @param array $payload
     */
    public function __construct(
        array $headers = ['alg' => 'none'],
        array $claims = [],
        Signature $signature = null,
        array $payload = ['', '']
    ) {
        $this->headers = $headers;
        $this->claims = $claims;
        $this->signature = $signature;
        $this->payload = $payload;
    }

    /**
     * Returns the token headers
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * Returns if the header is configured
     *
     * @param string $name
     *
     * @return bool
     */
    public function hasHeader(string $name): bool
    {
        return array_key_exists($name, $this->headers);
    }

    /**
     * Returns the value of a token header
     *
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getHeader(string $name, $default = null)
    {
        if ($this->hasHeader($name)) {
            return $this->headers[$name];
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested header is not configured');
        }

        return $default;
    }

    /**
     * Returns the token claim set
     *
     * @return array
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * Returns if the claim is configured
     *
     * @param string $name
     *
     * @return bool
     */
    public function hasClaim(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    /**
     * Returns the value of a token claim
     *
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getClaim(string $name, $default = null)
    {
        if ($this->hasClaim($name)) {
            return $this->claims[$name];
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested claim is not configured');
        }

        return $default;
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer $signer
     * @param Key $key
     *
     * @return bool
     */
    public function verify(Signer $signer, Key $key): bool
    {
        if ($this->signature === null || $this->headers['alg'] !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
    }

    /**
     * Determine if the token is expired.
     *
     * @param DateTimeInterface $now Defaults to the current time.
     *
     * @return bool
     */
    public function isExpired(DateTimeInterface $now = null)
    {
        if (!$this->hasClaim('exp')) {
            return false;
        }

        $now = $now ?: new DateTime();

        return $now->getTimestamp() > $this->getClaim('exp');
    }

    /**
     * Returns the token payload
     *
     * @return string
     */
    public function getPayload(): string
    {
        return $this->payload[0] . '.' . $this->payload[1];
    }

    /**
     * Returns an encoded representation of the token
     *
     * @return string
     */
    public function __toString(): string
    {
        $data = implode('.', $this->payload);

        if ($this->signature === null) {
            $data .= '.';
        }

        return $data;
    }
}
