<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter;
use Lcobucci\JWT\Signer\Ecdsa\SignatureConverter;

use const OPENSSL_KEYTYPE_EC;

abstract class Ecdsa extends OpenSSL
{
    private SignatureConverter $converter;

    public function __construct(?SignatureConverter $converter = null)
    {
        $this->converter = $converter ?? new MultibyteStringConverter();
    }

    /** @deprecated */
    public static function create(): Ecdsa
    {
        return new static(); // @phpstan-ignore-line
    }

    final public function sign(string $payload, Key $key): string
    {
        return $this->converter->fromAsn1(
            $this->createSignature($key->contents(), $key->passphrase(), $payload),
            $this->pointLength()
        );
    }

    final public function verify(string $expected, string $payload, Key $key): bool
    {
        return $this->verifySignature(
            $this->converter->toAsn1($expected, $this->pointLength()),
            $payload,
            $key->contents()
        );
    }

    /** {@inheritdoc} */
    final protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void
    {
        if ($type !== OPENSSL_KEYTYPE_EC) {
            throw InvalidKeyProvided::incompatibleKeyType(
                self::KEY_TYPE_MAP[OPENSSL_KEYTYPE_EC],
                self::KEY_TYPE_MAP[$type],
            );
        }

        $expectedKeyLength = $this->expectedKeyLength();

        if ($lengthInBits !== $expectedKeyLength) {
            throw InvalidKeyProvided::incompatibleKeyLength($expectedKeyLength, $lengthInBits);
        }
    }

    /** @internal */
    abstract public function expectedKeyLength(): int;

    /**
     * Returns the length of each point in the signature, so that we can calculate and verify R and S points properly
     *
     * @internal
     */
    abstract public function pointLength(): int;
}
