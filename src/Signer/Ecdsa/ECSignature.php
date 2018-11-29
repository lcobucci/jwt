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
use function dechex;
use function hexdec;
use function mb_strlen;
use function mb_substr;
use function pack;
use function str_pad;
use function unpack;

final class ECSignature implements PointsManipulator
{
    private const ASN1_SEQUENCE          = '30';
    private const ASN1_INTEGER           = '02';
    private const ASN1_LENGTH_2BYTES     = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER  = '00';

    public function toEcPoint(string $signature, int $partLength): string
    {
        $signature = unpack('H*', $signature)[1];
        if (mb_strlen($signature, '8bit') !== 2 * $partLength) {
            throw new InvalidArgumentException('Invalid length.');
        }
        $R = mb_substr($signature, 0, $partLength, '8bit');
        $S = mb_substr($signature, $partLength, null, '8bit');

        $R  = self::preparePositiveInteger($R);
        $Rl = (int) (mb_strlen($R, '8bit') / 2);
        $S  = self::preparePositiveInteger($S);
        $Sl = (int) (mb_strlen($S, '8bit') / 2);

        return pack(
            'H*',
            self::ASN1_SEQUENCE . ($Rl + $Sl + 4 > 128 ? self::ASN1_LENGTH_2BYTES : '') . dechex($Rl + $Sl + 4)
            . self::ASN1_INTEGER . dechex($Rl) . $R
            . self::ASN1_INTEGER . dechex($Sl) . $S
        );
    }

    public function fromEcPoint(string $signature, int $partLength): string
    {
        $hex = unpack('H*', $signature)[1];
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

        $Rl = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));
        $R  = self::retrievePositiveInteger(mb_substr($hex, 4, $Rl * 2, '8bit'));
        $R  = str_pad($R, $partLength, '0', STR_PAD_LEFT);

        $hex = mb_substr($hex, 4 + $Rl * 2, null, '8bit');
        if (mb_substr($hex, 0, 2, '8bit') !== self::ASN1_INTEGER) { // INTEGER
            throw new RuntimeException('Invalid data. Should contain an integer.');
        }
        $Sl = (int) hexdec(mb_substr($hex, 2, 2, '8bit'));
        $S  = self::retrievePositiveInteger(mb_substr($hex, 4, $Sl * 2, '8bit'));
        $S  = str_pad($S, $partLength, '0', STR_PAD_LEFT);

        return pack('H*', $R . $S);
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
