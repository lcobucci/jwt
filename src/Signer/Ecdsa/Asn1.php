<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use FG\ASN1\ASNObject;
use FG\ASN1\Universal\Integer;
use FG\ASN1\Universal\Sequence;
use InvalidArgumentException;
use const STR_PAD_LEFT;
use function assert;
use function bin2hex;
use function gmp_init;
use function gmp_strval;
use function hex2bin;
use function is_string;
use function mb_strlen;
use function mb_substr;
use function str_pad;

/**
 * Manipulates the digital signature using ASN.1
 *
 * @see https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
 */
final class Asn1 implements PointsManipulator
{
    public function fromEcPoint(string $signature, int $length): string
    {
        $sequence = ASNObject::fromBinary($signature);
        assert($sequence instanceof Sequence);

        $signature = '';

        foreach ($sequence->getChildren() as $child) {
            $signature .= str_pad($this->decToHex($child->getContent()), $length, '0', STR_PAD_LEFT);
        }

        $result = hex2bin($signature);
        assert(is_string($result));

        return $result;
    }

    public function toEcPoint(string $points, int $length): string
    {
        $points = bin2hex($points);

        if (mb_strlen($points, '8bit') !== 2 * $length) {
            throw new InvalidArgumentException('The length of given value is different than expected');
        }

        $pointR = mb_substr($points, 0, $length, '8bit');
        $pointS = mb_substr($points, $length, null, '8bit');

        $sequence = new Sequence();
        $sequence->addChildren(
            [
                new Integer(gmp_strval(gmp_init($pointR, 16))),
                new Integer(gmp_strval(gmp_init($pointS, 16))),
            ]
        );

        return $sequence->getBinary();
    }

    private function decToHex(string $value): string
    {
        $hex = gmp_strval(gmp_strval($value), 16);

        if (mb_strlen($hex, '8bit') % 2 !== 0) {
            $hex = '0' . $hex;
        }

        return $hex;
    }
}
