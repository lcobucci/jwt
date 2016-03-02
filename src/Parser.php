<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;

/**
 * This class parses the JWT strings and convert them into tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Parser
{
    /**
     * The data decoder
     *
     * @var Parsing\Decoder
     */
    private $decoder;

    /**
     * The claims factory
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    /**
     * Initializes the object
     *
     * @param Parsing\Decoder $decoder
     * @param ClaimFactory $claimFactory
     */
    public function __construct(
        Parsing\Decoder $decoder = null,
        ClaimFactory $claimFactory = null
    ) {
        $this->decoder = $decoder ?: new Parsing\Parser();
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
    }

    /**
     * Parses the JWT and returns a token
     *
     * @param string $jwt
     *
     * @return Token
     */
    public function parse(string $jwt): Token
    {
        $data = $this->splitJwt($jwt);
        $header = $this->parseHeader($data[0]);
        $claims = $this->parseClaims($data[1]);
        $signature = $this->parseSignature($header, $data[2]);

        foreach ($claims as $name => $value) {
            if (isset($header[$name])) {
                $header[$name] = $value;
            }
        }

        if ($signature === null) {
            unset($data[2]);
        }

        return new Token($header, $claims, $signature, $data);
    }

    /**
     * Splits the JWT string into an array
     *
     * @param string $jwt
     *
     * @return array
     *
     * @throws InvalidArgumentException When JWT don't have all parts
     */
    protected function splitJwt(string $jwt): array
    {
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
    protected function parseHeader(string $data): array
    {
        $header = (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (isset($header['enc'])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @param string $data
     *
     * @return array
     */
    protected function parseClaims(string $data): array
    {
        $claims = (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        foreach ($claims as $name => &$value) {
            $value = $this->claimFactory->create($name, $value);
        }

        return $claims;
    }

    /**
     * Returns the signature from given data
     *
     * @param array $header
     * @param string $data
     *
     * @return Signature|null
     */
    protected function parseSignature(array $header, string $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash);
    }
}
