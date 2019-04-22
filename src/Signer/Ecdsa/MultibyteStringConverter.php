<?php
declare(strict_types=1);

/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2018 Spomky-Labs
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 *
 * @link https://github.com/web-token/jwt-framework/blob/v1.2/src/Component/Core/Util/ECSignature.php
 */
namespace Lcobucci\JWT\Signer\Ecdsa;

use InvalidArgumentException;
use const STR_PAD_LEFT;
use function assert;
use function bin2hex;
use function dechex;
use function hex2bin;
use function hexdec;
use function is_string;
use function mb_strlen;
use function mb_substr;
use function str_pad;

/**
 * ECDSA signature converter using ext-mbstring
 *
 * @internal
 */
final class MultibyteStringConverter implements SignatureConverter
{
    private const ASN1_SEQUENCE          = '30';
    private const ASN1_INTEGER           = '02';
    private const ASN1_MAX_SINGLE_BYTE   = 128;
    private const ASN1_LENGTH_2BYTES     = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER  = '00';
    private const BYTE_SIZE              = 2;

    public function toAsn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);

        if (self::octetLength($signature) !== $length) {
            throw new InvalidArgumentException('Invalid signature length.');
        }

        $pointR = self::preparePositiveInteger(mb_substr($signature, 0, $length, '8bit'));
        $pointS = self::preparePositiveInteger(mb_substr($signature, $length, null, '8bit'));

        $lengthR = self::octetLength($pointR);
        $lengthS = self::octetLength($pointS);

        $totalLength  = $lengthR + $lengthS + self::BYTE_SIZE + self::BYTE_SIZE;
        $lengthPrefix = $totalLength > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';

        $asn1 = hex2bin(
            self::ASN1_SEQUENCE
            . $lengthPrefix . dechex($totalLength)
            . self::ASN1_INTEGER . dechex($lengthR) . $pointR
            . self::ASN1_INTEGER . dechex($lengthS) . $pointS
        );
        assert(is_string($asn1));

        return $asn1;
    }

    private static function octetLength(string $data): int
    {
        return (int) (mb_strlen($data, '8bit') / self::BYTE_SIZE);
    }

    private static function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, self::BYTE_SIZE, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER . $data;
        }

        while (mb_substr($data, 0, self::BYTE_SIZE, '8bit') === self::ASN1_NEGATIVE_INTEGER
            && mb_substr($data, 2, self::BYTE_SIZE, '8bit') <= self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    public function fromAsn1(string $signature, int $length): string
    {
        $message  = bin2hex($signature);
        $position = 0;

        if (self::readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_SEQUENCE) {
            throw new InvalidArgumentException('Invalid data. Should start with a sequence.');
        }

        if (self::readAsn1Content($message, $position, self::BYTE_SIZE) === self::ASN1_LENGTH_2BYTES) {
            $position += self::BYTE_SIZE;
        }

        $pointR = self::retrievePositiveInteger(self::readAsn1Integer($message, $position));
        $pointS = self::retrievePositiveInteger(self::readAsn1Integer($message, $position));

        $points = hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT) . str_pad($pointS, $length, '0', STR_PAD_LEFT));
        assert(is_string($points));

        return $points;
    }

    private static function readAsn1Content(string $message, int &$position, int $length): string
    {
        $content   = mb_substr($message, $position, $length, '8bit');
        $position += $length;

        return $content;
    }

    private static function readAsn1Integer(string $message, int &$position): string
    {
        if (self::readAsn1Content($message, $position, self::BYTE_SIZE) !== self::ASN1_INTEGER) {
            throw new InvalidArgumentException('Invalid data. Should contain an integer.');
        }

        $length = (int) hexdec(self::readAsn1Content($message, $position, self::BYTE_SIZE));

        return self::readAsn1Content($message, $position, $length * self::BYTE_SIZE);
    }

    private static function retrievePositiveInteger(string $data): string
    {
        while (mb_substr($data, 0, self::BYTE_SIZE, '8bit') === self::ASN1_NEGATIVE_INTEGER
            && mb_substr($data, 2, self::BYTE_SIZE, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }
}
