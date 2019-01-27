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
use RuntimeException;
use const STR_PAD_LEFT;
use function bin2hex;
use function dechex;
use function hex2bin;
use function hexdec;
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
    private const ASN1_LENGTH_2BYTES     = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER  = '00';

    public function toAsn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);

        if (mb_strlen($signature, '8bit') !== 2 * $length) {
            throw new InvalidArgumentException('Invalid length.');
        }

        $pointR  = self::preparePositiveInteger(mb_substr($signature, 0, $length, '8bit'));
        $pointS  = self::preparePositiveInteger(mb_substr($signature, $length, null, '8bit'));

        $lengthR = (int) (mb_strlen($pointR, '8bit') / 2);
        $lengthS = (int) (mb_strlen($pointS, '8bit') / 2);

        $totalLength = $lengthR + $lengthS + 4;

        return hex2bin(
            self::ASN1_SEQUENCE . ($totalLength > 128 ? self::ASN1_LENGTH_2BYTES : '') . dechex($totalLength)
            . self::ASN1_INTEGER . dechex($lengthR) . $pointR
            . self::ASN1_INTEGER . dechex($lengthS) . $pointS
        );
    }

    public function fromAsn1(string $signature, int $length): string
    {
        $hex = bin2hex($signature);

        if (mb_substr($hex, 0, 2, '8bit') !== self::ASN1_SEQUENCE) { // SEQUENCE
            throw new RuntimeException('Invalid data. Should start with a sequence.');
        }

        if (mb_substr($hex, 2, 2, '8bit') === self::ASN1_LENGTH_2BYTES) { // LENGTH > 128
            $hex = mb_substr($hex, 6, null, '8bit');
        } else {
            $hex = mb_substr($hex, 4, null, '8bit');
        }

        if (mb_substr($hex, 0, 2, '8bit') !== self::ASN1_INTEGER) { // INTEGER
            throw new RuntimeException('Invalid data. Should contain an integer.');
        }

        $lengthR = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));
        $pointR  = self::retrievePositiveInteger(mb_substr($hex, 4, $lengthR * 2, '8bit'));

        $hex = mb_substr($hex, 4 + $lengthR * 2, null, '8bit');

        if (mb_substr($hex, 0, 2, '8bit') !== self::ASN1_INTEGER) { // INTEGER
            throw new RuntimeException('Invalid data. Should contain an integer.');
        }

        $lengthS = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));

        $pointS = self::retrievePositiveInteger(
            mb_substr($hex, 4, $lengthS * 2, '8bit')
        );

        return hex2bin(
            str_pad($pointR, $length, '0', STR_PAD_LEFT)
            . str_pad($pointS, $length, '0', STR_PAD_LEFT)
        );
    }

    private static function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, 2, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER . $data;
        }

        while (mb_substr($data, 0, 2, '8bit') === self::ASN1_NEGATIVE_INTEGER
            && mb_substr($data, 2, 2, '8bit') <= self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    private static function retrievePositiveInteger(string $data): string
    {
        while (mb_substr($data, 0, 2, '8bit') === self::ASN1_NEGATIVE_INTEGER
            && mb_substr($data, 2, 2, '8bit') > self::ASN1_BIG_INTEGER_LIMIT) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }
}
