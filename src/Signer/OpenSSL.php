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
use function openssl_error_string;
use function openssl_free_key;
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

abstract class OpenSSL implements Signer
{
    protected const KEY_TYPE_MAP = [
        OPENSSL_KEYTYPE_RSA => 'RSA',
        OPENSSL_KEYTYPE_DSA => 'DSA',
        OPENSSL_KEYTYPE_DH => 'DH',
        OPENSSL_KEYTYPE_EC => 'EC',
    ];

    /**
     * @throws CannotSignPayload
     * @throws InvalidKeyProvided
     */
    final protected function createSignature(
        string $pem,
        string $passphrase,
        string $payload
    ): string {
        $key = $this->getPrivateKey($pem, $passphrase);

        try {
            $signature = '';

            if (! openssl_sign($payload, $signature, $key, $this->algorithm())) {
                throw CannotSignPayload::errorHappened($this->fullOpenSSLErrorString());
            }

            return $signature;
        } finally {
            $this->freeKey($key);
        }
    }

    /**
     * @return resource|OpenSSLAsymmetricKey
     *
     * @throws CannotSignPayload
     */
    private function getPrivateKey(string $pem, string $passphrase)
    {
        $privateKey = openssl_pkey_get_private($pem, $passphrase);
        $this->validateKey($privateKey);

        return $privateKey;
    }

    /** @throws InvalidKeyProvided */
    final protected function verifySignature(
        string $expected,
        string $payload,
        string $pem
    ): bool {
        $key    = $this->getPublicKey($pem);
        $result = openssl_verify($payload, $expected, $key, $this->algorithm());
        $this->freeKey($key);

        return $result === 1;
    }

    /**
     * @return resource|OpenSSLAsymmetricKey
     *
     * @throws InvalidKeyProvided
     */
    private function getPublicKey(string $pem)
    {
        $publicKey = openssl_pkey_get_public($pem);
        $this->validateKey($publicKey);

        return $publicKey;
    }

    /**
     * Raises an exception when the key type is not the expected type
     *
     * @param resource|OpenSSLAsymmetricKey|bool $key
     *
     * @throws InvalidKeyProvided
     */
    private function validateKey($key): void
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

    /** @param resource|OpenSSLAsymmetricKey $key */
    private function freeKey($key): void
    {
        if ($key instanceof OpenSSLAsymmetricKey) {
            return;
        }

        openssl_free_key($key); // Deprecated and no longer necessary as of PHP >= 8.0
    }

    /**
     * Returns which algorithm to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function algorithm(): int;
}
