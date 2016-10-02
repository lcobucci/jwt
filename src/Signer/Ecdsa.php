<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\EccAdapter;
use Mdanter\Ecc\EccFactory;
use Lcobucci\JWT\Signer\Ecdsa\KeyParser;

/**
 * Base class for ECDSA signers
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
abstract class Ecdsa implements Signer
{
    /**
     * @var EccAdapter
     */
    private $adapter;

    /**
     * @var KeyParser
     */
    private $keyParser;

    public static function create(): Ecdsa
    {
        $mathInterface = EccFactory::getAdapter();

        return new static(
            EccAdapter::create($mathInterface),
            KeyParser::create($mathInterface)
        );
    }

    public function __construct(EccAdapter $adapter, KeyParser $keyParser)
    {
        $this->adapter = $adapter;
        $this->keyParser = $keyParser;
    }

    /**
     * {@inheritdoc}
     */
    public function sign(string $payload, Key $key): string
    {
        return $this->adapter->createHash(
            $this->keyParser->getPrivateKey($key),
            $this->adapter->createSigningHash($payload, $this->getAlgorithm()),
            $this->getAlgorithm()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->adapter->verifyHash(
            $expected,
            $this->keyParser->getPublicKey($key),
            $this->adapter->createSigningHash($payload, $this->getAlgorithm()),
            $this->getAlgorithm()
        );
    }

    /**
     * Returns the name of algorithm to be used to create the signing hash
     *
     * @return string
     */
    abstract public function getAlgorithm(): string;
}
