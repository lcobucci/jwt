<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa\EccAdapter;
use Lcobucci\JWT\Signer\Ecdsa\KeyParser;
use Mdanter\Ecc\EccFactory;

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
        $this->adapter   = $adapter;
        $this->keyParser = $keyParser;
    }

    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
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
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->adapter->verifyHash(
            $expected,
            $this->keyParser->getPublicKey($key),
            $this->adapter->createSigningHash($payload, $this->getAlgorithm()),
            $this->getAlgorithm()
        );
    }

    abstract public function getAlgorithm(): string;
}
