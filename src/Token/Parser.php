<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
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
        [$encodedHeaders, $encodedClaims, $encodedSignature] = $this->splitJwt($jwt);

        $header = $this->parseHeader($encodedHeaders);

        return new Plain(
            new DataSet($header, $encodedHeaders),
            new DataSet($this->parseClaims($encodedClaims), $encodedClaims),
            $this->parseSignature($header, $encodedSignature)
        );
    }

    /**
     * Splits the JWT string into an array
     *
     * @throws InvalidArgumentException When JWT doesn't have all parts
     */
    private function splitJwt(string $jwt): array
    {
        $data = \explode('.', $jwt);

        if (\count($data) !== 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    /**
     * Parses the header from a string
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
     */
    private function parseClaims(string $data): array
    {
        $claims = (array) $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (isset($claims[RegisteredClaims::AUDIENCE])) {
            $claims[RegisteredClaims::AUDIENCE] = (array) $claims[RegisteredClaims::AUDIENCE];
        }

        foreach (\array_intersect(RegisteredClaims::DATE_CLAIMS, \array_keys($claims)) as $claim) {
            $claims[$claim] = $this->convertDate((string) $claims[$claim]);
        }

        return $claims;
    }

    private function convertDate(string $value): DateTimeImmutable
    {
        if (\strpos($value, '.') === false) {
            return new DateTimeImmutable('@' . $value);
        }

        return DateTimeImmutable::createFromFormat('U.u', $value);
    }

    /**
     * Returns the signature from given data
     */
    private function parseSignature(array $header, string $data): Signature
    {
        if ($data === '' || ! isset($header['alg']) || $header['alg'] === 'none') {
            return Signature::fromEmptyData();
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash, $data);
    }
}
