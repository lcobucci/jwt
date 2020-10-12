<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

interface Parser
{
    /**
     * Parses the JWT and returns a token
     *
     * @throws InvalidArgument
     */
    public function parse(string $jwt): Token;
}
