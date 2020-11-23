<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use BadMethodCallException;
use DateTime;
use DateTimeImmutable;
use DateTimeInterface;
use Generator;
use Lcobucci\JWT\Claim\Factory;
use Lcobucci\JWT\Claim\Validatable;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaims;
use OutOfBoundsException;
use function func_num_args;
use function implode;
use function in_array;
use function sprintf;

/**
 * Basic structure of the JWT
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Token
{
    /** @internal */
    const FAKE_DEFAULT_VALUE = '~~~WEIRD~DEFAULT~VALUE~~~';

    /**
     * The token headers
     *
     * @var DataSet
     */
    private $headers;

    /**
     * The token claim set
     *
     * @var DataSet
     */
    private $claims;

    /**
     * The token signature
     *
     * @var Signature|null
     */
    private $signature;

    /**
     * The encoded data
     *
     * @var array
     */
    private $payload;

    /**
     * @internal This serves just as compatibility layer
     *
     * @var Factory
     */
    private $claimFactory;

    /**
     * Initializes the object
     *
     * @param array $headers
     * @param array $claims
     * @param array $payload
     * @param Signature|null $signature
     * @param Factory|null $claimFactory
     */
    public function __construct(
        array $headers = ['alg' => 'none'],
        array $claims = [],
        Signature $signature = null,
        array $payload = ['', ''],
        Factory $claimFactory = null
    ) {
        $this->headers = new DataSet($headers, $payload[0]);
        $this->claims = new DataSet($claims, $payload[1]);
        $this->signature = $signature;
        $this->payload = $payload;
        $this->claimFactory = $claimFactory ?: new Factory();
    }

    /** @return DataSet */
    public function headers()
    {
        return $this->headers;
    }

    /**
     * Returns the token headers
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::headers()
     *
     * @return array
     */
    public function getHeaders()
    {
        $items = [];

        foreach ($this->headers->all() as $name => $value) {
            if (! in_array($name, RegisteredClaims::ALL, true) || ! $this->claims->has($name)) {
                $items[$name] = $value;
                continue;
            }

            $items[$name] = $this->claimFactory->create($name, $value);
        }

        return $items;
    }

    /**
     * Returns if the header is configured
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::headers()
     * @see DataSet::has()
     *
     * @param string $name
     *
     * @return boolean
     */
    public function hasHeader($name)
    {
        return $this->headers->has($name);
    }

    /**
     * Returns the value of a token header
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::headers()
     * @see DataSet::has()
     *
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getHeader($name, $default = null)
    {
        if (func_num_args() === 1) {
            $default = self::FAKE_DEFAULT_VALUE;
        }

        $value = $this->headers->get($name, $default);

        if ($value === self::FAKE_DEFAULT_VALUE) {
            throw new OutOfBoundsException(sprintf('Requested header "%s" is not configured', $name));
        }

        return $value;
    }

    /** @return DataSet */
    public function claims()
    {
        return $this->claims;
    }

    /**
     * Returns the token claim set
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::claims()
     *
     * @return array
     */
    public function getClaims()
    {
        $items = [];

        foreach ($this->claims->all() as $name => $value) {
            $items[$name] = $this->claimFactory->create($name, $value);
        }

        return $items;
    }

    /**
     * Returns if the claim is configured
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::claims()
     * @see DataSet::has()
     *
     * @param string $name
     *
     * @return boolean
     */
    public function hasClaim($name)
    {
        return $this->claims->has($name);
    }

    /**
     * Returns the value of a token claim
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::claims()
     * @see DataSet::get()
     *
     * @param string $name
     * @param mixed $default
     *
     * @return mixed
     *
     * @throws OutOfBoundsException
     */
    public function getClaim($name, $default = null)
    {
        if (func_num_args() === 1) {
            $default = self::FAKE_DEFAULT_VALUE;
        }

        $value = $this->claims->get($name, $default);

        if ($value === self::FAKE_DEFAULT_VALUE) {
            throw new OutOfBoundsException(sprintf('Requested header "%s" is not configured', $name));
        }

        if ($value instanceof DateTimeImmutable && in_array($name, RegisteredClaims::DATE_CLAIMS, true)) {
            $value = $value->getTimestamp();
        }

        return $value;
    }

    /**
     * Verify if the key matches with the one that created the signature
     *
     * @param Signer $signer
     * @param Key|string $key
     *
     * @return boolean
     *
     * @throws BadMethodCallException When token is not signed
     */
    public function verify(Signer $signer, $key)
    {
        if ($this->signature === null) {
            throw new BadMethodCallException('This token is not signed');
        }

        if ($this->headers->get('alg') !== $signer->getAlgorithmId()) {
            return false;
        }

        return $this->signature->verify($signer, $this->getPayload(), $key);
    }

    /**
     * Validates if the token is valid
     *
     * @param ValidationData $data
     *
     * @return boolean
     */
    public function validate(ValidationData $data)
    {
        foreach ($this->getValidatableClaims() as $claim) {
            if (!$claim->validate($data)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the token is expired.
     *
     * @param DateTimeInterface|null $now Defaults to the current time.
     *
     * @return bool
     */
    public function isExpired(DateTimeInterface $now = null)
    {
        if (! $this->claims->has('exp')) {
            return false;
        }

        $now = $now ?: new DateTimeImmutable();

        return $now > $this->claims->get(RegisteredClaims::EXPIRATION_TIME);
    }

    /**
     * Yields the validatable claims
     *
     * @return Generator
     */
    private function getValidatableClaims()
    {
        foreach ($this->getClaims() as $claim) {
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
    public function getPayload()
    {
        return $this->payload[0] . '.' . $this->payload[1];
    }

    /** @return Signature|null */
    public function signature()
    {
        return $this->signature;
    }

    /**
     * Returns an encoded representation of the token
     *
     * @deprecated This method has been removed from the interface in v4.0
     * @see Token::toString()
     *
     * @return string
     */
    public function __toString()
    {
        return $this->toString();
    }

    /** @return string */
    public function toString()
    {
        $data = implode('.', $this->payload);

        if ($this->signature === null) {
            $data .= '.';
        }

        return $data;
    }
}
