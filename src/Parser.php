<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;

interface Parser
{
    /**
     * Parses the JWT and returns a token
     *
     * @throws InvalidArgumentException When the given string isn't a valid JWT.
     * @throws CannotDecodeContent      When something goes wrong while decoding.
     * @throws UnsupportedHeaderFound   When parsed token has an unsupported header.
     */
    public function parse(string $jwt): Token;
}
