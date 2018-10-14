<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Ecdsa\Asn1;
use Lcobucci\JWT\Signer\Ecdsa\PointsManipulator;
use const OPENSSL_KEYTYPE_EC;

abstract class Ecdsa extends OpenSSL
{
    /**
     * @var PointsManipulator
     */
    private $manipulator;

    public function __construct(PointsManipulator $manipulator)
    {
        $this->manipulator = $manipulator;
    }

    public static function create(): Ecdsa
    {
        return new static(new Asn1());
    }

    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
    {
        return $this->manipulator->fromEcPoint(
            $this->createSignature($key->getContent(), $key->getPassphrase(), $payload),
            $this->getKeyLength()
        );
    }

    /**
     * {@inheritdoc}
     */
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature(
            $this->manipulator->toEcPoint($expected, $this->getKeyLength()),
            $payload,
            $key->getContent()
        );
    }

    /**
     * {@inheritdoc}
     */
    final public function getKeyType(): int
    {
        return OPENSSL_KEYTYPE_EC;
    }

    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     */
    abstract public function getKeyLength(): int;
}
