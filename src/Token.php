<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Generator;
use Lcobucci\JWT\Claim\Validatable;
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
<<<<<<< HEAD
     * @return boolean
     */
    public function hasHeader($name)
=======
     * @return bool
     */
    public function hasHeader(string $name): bool
>>>>>>> origin/master
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
<<<<<<< HEAD
    public function getHeader($name, $default = null)
=======
    public function getHeader(string $name, $default = null)
>>>>>>> origin/master
    {
        if ($this->hasHeader($name)) {
            return $this->getHeaderValue($name);
        }

        if ($default === null) {
            throw new OutOfBoundsException('Requested header is not configured');
        }

        return $default;
    }

    /**
     * Returns the value stored in header
     *
     * @param string $name
     *
     * @return mixed
     */
<<<<<<< HEAD
    private function getHeaderValue($name)
=======
    private function getHeaderValue(string $name)
>>>>>>> origin/master
    {
        $header = $this->headers[$name];

        if ($header instanceof Claim) {
            return $header->getValue();
        }

        return $header;
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
<<<<<<< HEAD
     * @return boolean
     */
    public function hasClaim($name)
=======
     * @return bool
     */
    public function hasClaim(string $name): bool
>>>>>>> origin/master
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
<<<<<<< HEAD
    public function getClaim($name, $default = null)
=======
    public function getClaim(string $name, $default = null)
>>>>>>> origin/master
    {
        if ($this->hasClaim($name)) {
            return $this->claims[$name]->getValue();
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
     * @param Key|string $key
     *
     * @return bool
     */
    public function verify(Signer $signer, $key): bool
    {
        if ($this->signature === null || $this->headers['alg'] !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
    }

    /**
     * Validates if the token is valid
     *
     * @param ValidationData $data
     *
     * @return bool
     */
    public function validate(ValidationData $data): bool
    {
        foreach ($this->getValidatableClaims() as $claim) {
            if (!$claim->validate($data)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Yields the validatable claims
     *
     * @return Generator
     */
    private function getValidatableClaims(): Generator
    {
        foreach ($this->claims as $claim) {
            if ($claim instanceof Validatable) {
                yield $claim;
            }
        }
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
