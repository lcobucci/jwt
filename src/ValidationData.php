<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

/**
 * Class that wraps validation values
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.0.0
 */
class ValidationData
{
    /**
     * The list of things to be validated
     *
     * @var array
     */
    private $items;

    /**
     * Initializes the object
     *
     * @param int|null $currentTime
     */
    public function __construct(int $currentTime = null)
    {
        $currentTime = $currentTime ?: time();

        $this->items = [
            'jti' => null,
            'iss' => null,
            'aud' => null,
            'sub' => null,
            'iat' => $currentTime,
            'nbf' => $currentTime,
            'exp' => $currentTime
        ];
    }

    /**
     * Configures the id
     *
     * @param string $id
     */
    public function setId(string $id)
    {
        $this->items['jti'] = $id;
    }

    /**
     * Configures the issuer
     *
     * @param string $issuer
     */
    public function setIssuer(string $issuer)
    {
        $this->items['iss'] = $issuer;
    }

    /**
     * Configures the audience
     *
     * @param string $audience
     */
    public function setAudience(string $audience)
    {
        $this->items['aud'] = $audience;
    }

    /**
     * Configures the subject
     *
     * @param string $subject
     */
    public function setSubject(string $subject)
    {
        $this->items['sub'] = $subject;
    }

    /**
     * Configures the time that "iat", "nbf" and "exp" should be based on
     *
     * @param int $currentTime
     */
    public function setCurrentTime(int $currentTime)
    {
        $this->items['iat'] = $currentTime;
        $this->items['nbf'] = $currentTime;
        $this->items['exp'] = $currentTime;
    }

    /**
     * Returns the requested item
     *
     * @param string $name
     *
     * @return mixed
     */
    public function get(string $name)
    {
        return $this->items[$name] ?? null;
    }

    /**
     * Returns if the item is present
     *
     * @param string $name
     *
     * @return bool
     */
    public function has(string $name): bool
    {
        return !empty($this->items[$name]);
    }
}
