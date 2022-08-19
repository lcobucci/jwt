<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\CannotEncodeContent;

interface Encoder
{
    /**
     * Encodes to JSON, validating the errors
     *
     * @throws CannotEncodeContent When something goes wrong while encoding.
     */
    public function jsonEncode(mixed $data): string;

    /**
     * Encodes to base64url
     *
     * @link http://tools.ietf.org/html/rfc4648#section-5
     */
    public function base64UrlEncode(string $data): string;
}
