<?php

namespace Lcobucci\JWT\Encoding;

use JsonException;
use Lcobucci\JWT\Exception;
use RuntimeException;

final class CannotDecodeContent extends RuntimeException implements Exception
{
    /**
     * @param JsonException $previous
     *
     * @return self
     */
    public static function jsonIssues(JsonException $previous)
    {
        return new self('Error while decoding from JSON', 0, $previous);
    }

    /** @return self */
    public static function invalidBase64String()
    {
        return new self('Error while decoding from Base64Url, invalid base64 characters detected');
    }
}
