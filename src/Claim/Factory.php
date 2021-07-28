<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Claim;

use DateTimeImmutable;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Token\RegisteredClaims;
use function current;
use function in_array;
use function is_array;

/**
 * Class that create claims
 *
 * @deprecated This class will be removed on v4
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class Factory
{
    /**
     * The list of claim callbacks
     *
     * @var array
     */
    private $callbacks;

    /**
     * Initializes the factory, registering the default callbacks
     *
     * @param array $callbacks
     */
    public function __construct(array $callbacks = [])
    {
        $compared = new Compared();
        $this->callbacks = array_merge(
            [
                'iat' => [$compared, 'createLesserOrEqualsTo'],
                'nbf' => [$compared, 'createLesserOrEqualsTo'],
                'exp' => [$compared, 'createGreaterOrEqualsTo'],
                'iss' => [$compared, 'createEqualsTo'],
                'aud' => [$compared, 'createEqualsTo'],
                'sub' => [$compared, 'createEqualsTo'],
                'jti' => [$compared, 'createEqualsTo']
            ],
            $callbacks
        );
    }

    /**
     * Create a new claim
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Claim
     */
    public function create($name, $value)
    {
        if ($value instanceof DateTimeImmutable && in_array($name, RegisteredClaims::DATE_CLAIMS, true)) {
            $value = $value->getTimestamp();
        }

        if ($name === RegisteredClaims::AUDIENCE && is_array($value)) {
            $value = current($value);
        }

        if (!empty($this->callbacks[$name])) {
            return call_user_func($this->callbacks[$name], $name, $value);
        }

        return $this->createBasic($name, $value);
    }

    /**
     * Creates a basic claim
     *
     * @param string $name
     * @param mixed $value
     *
     * @return Basic
     */
    private function createBasic($name, $value)
    {
        return new Basic($name, $value);
    }
}
