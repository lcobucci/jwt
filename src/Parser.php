<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Encoding\CannotDecodeContent;

interface Parser
{
    /**
     * Parses the JWT and returns a token
     *
     * @throws InvalidArgumentException When the given string isn't a valid JWT.
     * @throws CannotDecodeContent      When something goes wrong while decoding.
     */
    public function parse(string $jwt): Token;
}
