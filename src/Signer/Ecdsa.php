<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Lcobucci\JWT\Signer\Ecdsa\SignatureConverter;
use const OPENSSL_KEYTYPE_EC;

abstract class Ecdsa extends OpenSSL
{
    /**
     * @var SignatureConverter
     */
    private $converter;

    public function __construct(SignatureConverter $converter)
    {
        $this->converter = $converter;
    }

    public static function create(): Ecdsa
    {
        return new static(new MultibyteStringConverter());
    }

    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
    {
        return $this->converter->fromAsn1(
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
            $this->converter->toAsn1($expected, $this->getKeyLength()),
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
