<?php

declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;

/**
 * This class parses the JWT strings and convert them into tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
interface Parser
{
    /**
     * Parses the JWT and returns a token
     *
     * @throws InvalidArgumentException
     */
    public function parse(string $jwt): Token;
}
