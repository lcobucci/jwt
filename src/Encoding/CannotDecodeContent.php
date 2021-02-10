<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use JsonException;
use Lcobucci\JWT\Exception;
use RuntimeException;
use SodiumException;

final class CannotDecodeContent extends RuntimeException implements Exception
{
    public static function jsonIssues(JsonException $previous): self
    {
        return new self('Error while decoding from JSON', 0, $previous);
    }

    public static function invalidBase64String(SodiumException $sodiumException): self
    {
        return new self('Error while decoding from Base64Url, invalid base64 characters detected', 0, $sodiumException);
    }
}
