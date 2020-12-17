<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use JsonException;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use SodiumException;

use function json_decode;
use function json_encode;
use function sodium_base642bin;
use function sodium_bin2base64;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;

/**
 * A utilitarian class that encodes and decodes data according with JOSE specifications
 */
final class JoseEncoder implements Encoder, Decoder
{
    private const JSON_DEFAULT_DEPTH = 512;

    /** @inheritdoc */
    public function jsonEncode($data): string
    {
        try {
            return json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw CannotEncodeContent::jsonIssues($exception);
        }
    }

    /** @inheritdoc */
    public function jsonDecode(string $json)
    {
        try {
            return json_decode($json, true, self::JSON_DEFAULT_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw CannotDecodeContent::jsonIssues($exception);
        }
    }

    public function base64UrlEncode(string $data): string
    {
        return sodium_bin2base64($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    public function base64UrlDecode(string $data): string
    {
        try {
            return sodium_base642bin($data, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, '');
        } catch (SodiumException $sodiumException) {
            throw CannotDecodeContent::invalidBase64String($sodiumException);
        }
    }
}
