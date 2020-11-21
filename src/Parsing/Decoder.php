<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Parsing;

use JsonException;
use Lcobucci\JWT\Encoding\CannotDecodeContent;
use RuntimeException;

use function json_decode;
use function json_last_error;
use function json_last_error_msg;

/**
 * Class that decodes data according with the specs of RFC-4648
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @link http://tools.ietf.org/html/rfc4648#section-5
 */
class Decoder
{
    /**
     * Decodes from JSON, validating the errors (will return an associative array
     * instead of objects)
     *
     * @param string $json
     * @return mixed
     *
     * @throws RuntimeException When something goes wrong while decoding
     */
    public function jsonDecode($json)
    {
        if (PHP_VERSION_ID < 70300) {
            $data = json_decode($json);

            if (json_last_error() != JSON_ERROR_NONE) {
                throw CannotDecodeContent::jsonIssues(new JsonException(json_last_error_msg()));
            }

            return $data;
        }

        try {
            return json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw CannotDecodeContent::jsonIssues($exception);
        }
    }

    /**
     * Decodes from base64url
     *
     * @param string $data
     * @return string
     */
    public function base64UrlDecode($data)
    {
        if ($remainder = strlen($data) % 4) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($data, '-_', '+/'));
    }
}
