<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

interface Signature
{
    /** @return non-empty-string */
    public function hash(): string;

    /**
     * Returns the encoded version of the signature
     *
     * @return non-empty-string
     */
    public function toString(): string;
}
