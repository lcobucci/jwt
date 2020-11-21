<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Parsing;

use JsonException;
use Lcobucci\JWT\Encoding\CannotEncodeContent;
use RuntimeException;

use function json_encode;
use function json_last_error;
use function json_last_error_msg;

/**
 * Class that encodes data according with the specs of RFC-4648
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @link http://tools.ietf.org/html/rfc4648#section-5
 */
class Encoder
{
    /**
     * Encodes to JSON, validating the errors
     *
     * @param mixed $data
     * @return string
     *
     * @throws RuntimeException When something goes wrong while encoding
     */
    public function jsonEncode($data)
    {
        if (PHP_VERSION_ID < 70300) {
            $json = json_encode($data);

            if (json_last_error() != JSON_ERROR_NONE) {
                throw CannotEncodeContent::jsonIssues(new JsonException(json_last_error_msg()));
            }

            return $json;
        }

        try {
            return json_encode($data, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw CannotEncodeContent::jsonIssues($exception);
        }
    }

    /**
     * Encodes to base64url
     *
     * @param string $data
     * @return string
     */
    public function base64UrlEncode($data)
    {
        return str_replace('=', '', strtr(base64_encode($data), '+/', '-_'));
    }
}
