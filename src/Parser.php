<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Factory;

/**
 * This class parses the JWT strings and convert them into tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Parser
{
    /**
     * The data encoder
     *
     * @var Encoder
     */
    private $encoder;

    /**
     * The data decoder
     *
     * @var Decoder
     */
    private $decoder;

    /**
     * The signer factory
     *
     * @var Factory
     */
    private $factory;

    /**
     * Initializes the object
     *
     * @param Encoder $encoder
     * @param Decoder $decoder
     * @param Factory $factory
     */
    public function __construct(
        Encoder $encoder = null,
        Decoder $decoder = null,
        Factory $factory = null
    ) {
        $this->encoder = $encoder ?: new Encoder();
        $this->decoder = $decoder ?: new Decoder();
        $this->factory = $factory ?: new Factory();
    }

    /**
     * Parses the JWT and returns a token
     *
     * @param string $jwt
     * @return Token
     */
    public function parse($jwt)
    {
        $data = $this->splitJwt($jwt);

        $token = new Token(
            $header = $this->parseHeader($data[0]),
            $this->parseClaims($data[1]),
            $this->parseSignature($header, $data[2])
        );

        $token->setEncoder($this->encoder);

        return $token;
    }

    /**
     * Slipts the JWT string into an array
     *
     * @param string $jwt
     *
     * @return array
     *
     * @throws InvalidArgumentException When JWT is not a string or is invalid
     */
    protected function splitJwt($jwt)
    {
        if (!is_string($jwt)) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        $data = explode('.', $jwt);

        if (count($data) != 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    /**
     * Parses the header from a string
     *
     * @param string $data
     *
     * @return array
     *
     * @throws InvalidArgumentException When an invalid header is informed
     */
    protected function parseHeader($data)
    {
        $header = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (!is_array($header) || isset($header['enc'])) {
            throw new InvalidArgumentException('That header is not a valid array or uses encryption');
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @param string $data
     *
     * @return array
     *
     * @throws InvalidArgumentException When an invalid claim set is informed
     */
    protected function parseClaims($data)
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (!is_array($claims)) {
            throw new InvalidArgumentException('That claims are not valid');
        }

        return $claims;
    }

    /**
     * Returns the signature from given data
     *
     * @param array $header
     * @param string $data
     *
     * @return Signature
     */
    protected function parseSignature(array $header, $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($this->factory->create($header['alg']), $hash);
    }
}
