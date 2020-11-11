<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as TokenInterface;

use function array_key_exists;
use function count;
use function explode;
use function is_array;
use function strpos;

final class Parser implements ParserInterface
{
    private Decoder $decoder;

    public function __construct(Decoder $decoder)
    {
        $this->decoder = $decoder;
    }

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

        if (array_key_exists('enc', $header)) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        if (! array_key_exists('typ', $header)) {
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

        if (array_key_exists(RegisteredClaims::AUDIENCE, $claims)) {
            $claims[RegisteredClaims::AUDIENCE] = (array) $claims[RegisteredClaims::AUDIENCE];
        }

        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (! array_key_exists($claim, $claims)) {
                continue;
            }

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
        if ($data === '' || ! array_key_exists('alg', $header) || $header['alg'] === 'none') {
            return Signature::fromEmptyData();
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($hash, $data);
    }
}
