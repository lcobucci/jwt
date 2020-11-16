<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use JsonException;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;

use function base64_decode;
use function base64_encode;
use function is_string;
use function json_decode;
use function json_encode;
use function rtrim;
use function strtr;

use const JSON_THROW_ON_ERROR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

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
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function base64UrlDecode(string $data): string
    {
        // Padding isn't added back because it isn't strictly necessary for decoding with PHP
        $decodedContent = base64_decode(strtr($data, '-_', '+/'), true);

        if (! is_string($decodedContent)) {
            throw CannotDecodeContent::invalidBase64String();
        }

        return $decodedContent;
    }
}
