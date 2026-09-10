<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;
use OpenSSLAsymmetricKey;

use function array_key_exists;
use function assert;
use function is_array;
use function is_bool;
use function is_int;
use function is_string;
use function openssl_error_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

use const OPENSSL_KEYTYPE_DH;
use const OPENSSL_KEYTYPE_DSA;
use const OPENSSL_KEYTYPE_EC;
use const OPENSSL_KEYTYPE_RSA;
use const PHP_EOL;

abstract readonly class OpenSSL implements Signer
{
    protected const array KEY_TYPE_MAP = [
        OPENSSL_KEYTYPE_RSA => 'RSA',
        OPENSSL_KEYTYPE_DSA => 'DSA',
        OPENSSL_KEYTYPE_DH => 'DH',
        OPENSSL_KEYTYPE_EC => 'EC',
    ];

    /**
     * @return non-empty-string
     *
     * @throws CannotSignPayload
     * @throws InvalidKeyProvided
     */
    final protected function createSignature(
        Key $key,
        string $payload,
    ): string {
        $opensslKey = $this->getPrivateKey($key);

        $signature = '';

        if (! openssl_sign($payload, $signature, $opensslKey, $this->algorithm())) {
            throw CannotSignPayload::errorHappened($this->fullOpenSSLErrorString());
        }

        return $signature;
    }

    /** @throws CannotSignPayload */
    private function getPrivateKey(
        Key $key,
    ): OpenSSLAsymmetricKey {
        return $this->validateKey(openssl_pkey_get_private($key->contents(), $key->passphrase()));
    }

    /** @throws InvalidKeyProvided */
    final protected function verifySignature(
        string $expected,
        string $payload,
        Key $key,
    ): bool {
        $opensslKey = $this->getPublicKey($key);
        $result     = openssl_verify($payload, $expected, $opensslKey, $this->algorithm());

        return $result === 1;
    }

    /** @throws InvalidKeyProvided */
    private function getPublicKey(Key $key): OpenSSLAsymmetricKey
    {
        return $this->validateKey(openssl_pkey_get_public($key->contents()));
    }

    /**
     * Raises an exception when the key type is not the expected type
     *
     * @throws InvalidKeyProvided
     */
    private function validateKey(OpenSSLAsymmetricKey|bool $key): OpenSSLAsymmetricKey
    {
        if (is_bool($key)) {
            throw InvalidKeyProvided::cannotBeParsed($this->fullOpenSSLErrorString());
        }

        $details = openssl_pkey_get_details($key);
        assert(is_array($details));

        assert(array_key_exists('bits', $details));
        assert(is_int($details['bits']));
        assert(array_key_exists('type', $details));
        assert(is_int($details['type']));

        $this->guardAgainstIncompatibleKey($details['type'], $details['bits']);
        $this->guardAgainstIncompatibleCurve($this->curveNameFrom($details));

        return $key;
    }

    /** @param array<string, mixed> $details */
    private function curveNameFrom(array $details): ?string
    {
        if (! isset($details['ec']['curve_name'])) {
            return null;
        }

        $curveName = $details['ec']['curve_name'];
        assert(is_string($curveName));

        return $curveName;
    }

    private function fullOpenSSLErrorString(): string
    {
        $error = '';

        while ($msg = openssl_error_string()) {
            $error .= PHP_EOL . '* ' . $msg;
        }

        return $error;
    }

    /** @throws InvalidKeyProvided */
    abstract protected function guardAgainstIncompatibleKey(int $type, int $lengthInBits): void;

    /**
     * Raises an exception when the key curve is not the expected one
     *
     * The default implementation performs no check; only algorithms that are sensitive to the
     * curve (e.g. ECDSA-based ones) need to override this.
     *
     * @throws InvalidKeyProvided
     */
    // phpcs:ignore SlevomatCodingStandard.Functions.UnusedParameter
    protected function guardAgainstIncompatibleCurve(?string $curveName): void
    {
    }

    /**
     * Returns which algorithm to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function algorithm(): int;
}
