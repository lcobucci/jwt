<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use GMP;
use InvalidArgumentException;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Crypto\Signature\Signer;
use Mdanter\Ecc\Curves\NistCurve;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Math\GmpMathInterface;
use Mdanter\Ecc\Primitives\GeneratorPoint;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Random\RandomNumberGeneratorInterface;

/**
 * PHPECC adapter in order to simplify ECDSA base signer
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
class EccAdapter
{
    const GENERATOR_POINTS = [
        'sha256' => 'generator256',
        'sha384' => 'generator384',
        'sha512' => 'generator521',
    ];

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var SignatureSerializer
     */
    private $serializer;

    /**
     * @var RandomNumberGeneratorInterface
     */
    private $numberGenerator;

    /**
     * @var NistCurve
     */
    private $nistCurve;

    public static function create(GmpMathInterface $mathInterface): EccAdapter
    {
        return new self(
            EccFactory::getSigner($mathInterface),
            EccFactory::getNistCurves($mathInterface),
            new SignatureSerializer($mathInterface),
            RandomGeneratorFactory::getRandomGenerator()
        );
    }

    public function __construct(
        Signer $signer,
        NistCurve $nistCurve,
        SignatureSerializer $serializer,
        RandomNumberGeneratorInterface $numberGenerator
    ) {
        $this->signer = $signer;
        $this->nistCurve = $nistCurve;
        $this->serializer = $serializer;
        $this->numberGenerator = $numberGenerator;
    }

    public function createHash(
        PrivateKeyInterface $key,
        GMP $signingHash,
        string $algorithm
    ): string {
        return $this->serializer->serialize(
            $this->signer->sign(
                $key,
                $signingHash,
                $this->numberGenerator->generate($key->getPoint()->getOrder())
            ),
            $algorithm
        );
    }

    public function verifyHash(
        string $expected,
        PublicKeyInterface $key,
        GMP $signingHash,
        string $algorithm
    ): bool {
        return $this->signer->verify(
            $key,
            $this->serializer->parse($expected, $algorithm),
            $signingHash
        );
    }

    public function createSigningHash(
        string $payload,
        string $algorithm
    ): GMP {
        return $this->signer->hashData(
            $this->generatorPoint($algorithm),
            $algorithm,
            $payload
        );
    }

    private function generatorPoint(string $algorithm): GeneratorPoint
    {
        if (!array_key_exists($algorithm, self::GENERATOR_POINTS)) {
            throw new InvalidArgumentException('Unknown algorithm');
        }

        return $this->nistCurve->{self::GENERATOR_POINTS[$algorithm]}(
            $this->numberGenerator
        );
    }
}
