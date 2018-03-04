<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key;

interface Signer
{
    /**
     * Returns the algorithm id
     */
    public function getAlgorithmId(): string;

    /**
     * Creates a hash for the given payload
     *
     * @throws InvalidArgumentException When given key is invalid.
     */
    public function sign(string $payload, Key $key): string;

    /**
     * Returns if the expected hash matches with the data and key
     *
     * @throws InvalidArgumentException When given key is invalid.
     */
    public function verify(string $expected, string $payload, Key $key): bool;
}
