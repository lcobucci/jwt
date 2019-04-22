<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as TokenInterface;
use function array_intersect;
use function array_keys;
use function count;
use function explode;
use function is_array;
use function strpos;

final class Parser implements ParserInterface
{
    /**
     * @var Parsing\Decoder
     */
    private $decoder;

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
     * @return string[]
     *
     * @throws InvalidArgumentException When JWT doesn't have all parts.
     */
    private function splitJwt(string $jwt): array
    {
        $data = explode('.', $jwt);

        if (count($data) !== 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    /**
     * Parses the header from a string
     *
     * @return mixed[]
     *
     * @throws InvalidArgumentException When an invalid header is informed.
     */
    private function parseHeader(string $data): array
    {
        $header = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (! is_array($header)) {
            throw new InvalidArgumentException('Headers must be an array');
        }

        if (isset($header['enc'])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        if (! isset($header['typ'])) {
            throw new InvalidArgumentException('The header "typ" must be present');
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @return mixed[]
     *
     * @throws InvalidArgumentException When an invalid claim set is informed.
     */
    private function parseClaims(string $data): array
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (! is_array($claims)) {
            throw new InvalidArgumentException('Claims must be an array');
        }

        if (isset($claims[RegisteredClaims::AUDIENCE])) {
            $claims[RegisteredClaims::AUDIENCE] = (array) $claims[RegisteredClaims::AUDIENCE];
        }

        foreach (array_intersect(RegisteredClaims::DATE_CLAIMS, array_keys($claims)) as $claim) {
            $claims[$claim] = $this->convertDate((string) $claims[$claim]);
        }

        return $claims;
    }

    private function convertDate(string $value): DateTimeImmutable
    {
        if (strpos($value, '.') === false) {
            return new DateTimeImmutable('@' . $value);
        }

        $date = DateTimeImmutable::createFromFormat('U.u', $value);

        if ($date === false) {
            throw new InvalidArgumentException('Given value is not in the allowed format: ' . $value);
        }

        return $date;
    }

    /**
     * Returns the signature from given data
     *
     * @param mixed[] $header
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
