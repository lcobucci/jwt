<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use GMP;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Math\GmpMathInterface;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
class SignatureSerializer
{
    const LENGTH = [
        'sha256' => 64,
        'sha384' => 96,
        'sha512' => 132,
    ];

    const GMP_BASE = 10;

    /**
     * @var GmpMathInterface
     */
    private $mathInterface;

    public function __construct(GmpMathInterface $mathInterface)
    {
        $this->mathInterface = $mathInterface;
    }

    public function serialize(SignatureInterface $signature, string $algorithm): string
    {
        return pack(
            'H*',
            sprintf(
                '%s%s',
                $this->addPadding($signature->getR(), self::LENGTH[$algorithm]),
                $this->addPadding($signature->getS(), self::LENGTH[$algorithm])
            )
        );
    }

    private function addPadding(GMP $point, int $length): string
    {
        return str_pad(
            $this->mathInterface->decHex((string) $point),
            $length,
            '0',
            STR_PAD_LEFT
        );
    }

    public function parse(string $expected, string $algorithm): SignatureInterface
    {
        list($pointR, $pointS) = str_split(
            unpack('H*', $expected)[1],
            self::LENGTH[$algorithm]
        );

        return new Signature(
            gmp_init($this->mathInterface->hexDec($pointR), self::GMP_BASE),
            gmp_init($this->mathInterface->hexDec($pointS), self::GMP_BASE)
        );
    }
}
