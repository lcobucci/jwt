<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Parser as ParserInterface;
use Lcobucci\JWT\Token as TokenInterface;

use function array_key_exists;
use function count;
use function explode;
use function is_array;
use function is_numeric;
use function number_format;

final class Parser implements ParserInterface
{
    private const MICROSECOND_PRECISION = 6;

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
     * @throws InvalidTokenStructure When JWT doesn't have all parts.
     */
    private function splitJwt(string $jwt): array
    {
        $data = explode('.', $jwt);

        if (count($data) !== 3) {
            throw InvalidTokenStructure::missingOrNotEnoughSeparators();
        }

        return $data;
    }

    /**
     * Parses the header from a string
     *
     * @return mixed[]
     *
     * @throws UnsupportedHeaderFound When an invalid header is informed.
     * @throws InvalidTokenStructure  When parsed content isn't an array.
     */
    private function parseHeader(string $data): array
    {
        $header = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (! is_array($header)) {
            throw InvalidTokenStructure::arrayExpected('headers');
        }

        if (array_key_exists('enc', $header)) {
            throw UnsupportedHeaderFound::encryption();
        }

        if (! array_key_exists('typ', $header)) {
            $header['typ'] = 'JWT';
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @return mixed[]
     *
     * @throws InvalidTokenStructure When parsed content isn't an array or contains non-parseable dates.
     */
    private function parseClaims(string $data): array
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (! is_array($claims)) {
            throw InvalidTokenStructure::arrayExpected('claims');
        }

        if (array_key_exists(RegisteredClaims::AUDIENCE, $claims)) {
            $claims[RegisteredClaims::AUDIENCE] = (array) $claims[RegisteredClaims::AUDIENCE];
        }

        foreach (RegisteredClaims::DATE_CLAIMS as $claim) {
            if (! array_key_exists($claim, $claims)) {
                continue;
            }

            $claims[$claim] = $this->convertDate($claims[$claim]);
        }

        return $claims;
    }

    /**
     * @param int|float|string $timestamp
     *
     * @throws InvalidTokenStructure
     */
    private function convertDate($timestamp): DateTimeImmutable
    {
        if (! is_numeric($timestamp)) {
            throw InvalidTokenStructure::dateIsNotParseable($timestamp);
        }

        $normalizedTimestamp = number_format((float) $timestamp, self::MICROSECOND_PRECISION, '.', '');

        $date = DateTimeImmutable::createFromFormat('U.u', $normalizedTimestamp);

        if ($date === false) {
            throw InvalidTokenStructure::dateIsNotParseable($normalizedTimestamp);
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
