<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use InvalidArgumentException;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as TokenInterface;

/**
 * This class parses the JWT strings and convert them into tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class Parser implements ParserInterface
{
    /**
     * The data decoder
     *
     * @var Parsing\Decoder
     */
    private $decoder;

    /**
     * Initializes the object
     */
    public function __construct(Parsing\Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

    /**
     * {@inheritdoc}
     */
    public function parse(string $jwt): TokenInterface
    {
        list($encodedHeaders, $encodedClaims, $encodedSignature) = $this->splitJwt($jwt);

        $header = $this->parseHeader($encodedHeaders);
        $claims = $this->parseClaims($encodedClaims);
        $signature = $this->parseSignature($header, $encodedSignature);

        foreach ($claims as $name => $value) {
            if (isset($header[$name])) {
                $header[$name] = $value;
            }
        }

        return new Plain(
            new DataSet($header, $encodedHeaders),
            new DataSet($claims, $encodedClaims),
            $signature
        );
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
    private function splitJwt(string $jwt): array
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
    private function parseHeader(string $data): array
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
    private function parseClaims(string $data): array
    {
        return (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));
    }

    /**
     * Returns the signature from given data
     *
     * @param array $header
     * @param string $data
     *
     * @return Signature
     */
    private function parseSignature(array $header, string $data): Signature
    {
        if ($data === '' || !isset($header['alg']) || $header['alg'] === 'none') {
            return new Signature('', '');
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash, $data);
    }
}
