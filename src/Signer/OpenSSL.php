<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;
use function assert;
use function is_array;
use function is_resource;
use function openssl_error_string;
use function openssl_free_key;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_pkey_get_public;
use function openssl_sign;
use function openssl_verify;

abstract class OpenSSL implements Signer
{
    final protected function createSignature(
        string $pem,
        string $passphrase,
        string $payload
    ): string {
        $key = $this->getPrivateKey($pem, $passphrase);

        try {
            $signature = '';

            if (! openssl_sign($payload, $signature, $key, $this->getAlgorithm())) {
                throw new InvalidArgumentException(
                    'There was an error while creating the signature: ' . openssl_error_string()
                );
            }

            return $signature;
        } finally {
            openssl_free_key($key);
        }
    }

    /**
     * @return resource
     */
    private function getPrivateKey(string $pem, string $passphrase)
    {
        $privateKey = openssl_pkey_get_private($pem, $passphrase);
        $this->validateKey($privateKey);
        assert(is_resource($privateKey));

        return $privateKey;
    }

    final protected function verifySignature(
        string $expected,
        string $payload,
        string $pem
    ): bool {
        $key    = $this->getPublicKey($pem);
        $result = openssl_verify($payload, $expected, $key, $this->getAlgorithm());
        openssl_free_key($key);

        return $result === 1;
    }

    /**
     * @return resource
     */
    private function getPublicKey(string $pem)
    {
        $publicKey = openssl_pkey_get_public($pem);
        $this->validateKey($publicKey);
        assert(is_resource($publicKey));

        return $publicKey;
    }

    /**
     * Raises an exception when the key type is not the expected type
     *
     * @param resource|bool $key
     *
     * @throws InvalidArgumentException
     */
    private function validateKey($key): void
    {
        if (! is_resource($key)) {
            throw new InvalidArgumentException(
                'It was not possible to parse your key, reason: ' . openssl_error_string()
            );
        }

        $details = openssl_pkey_get_details($key);
        assert(is_array($details));

        if (! isset($details['key']) || $details['type'] !== $this->getKeyType()) {
            throw new InvalidArgumentException('This key is not compatible with this signer');
        }
    }

    /**
     * Returns the type of key to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function getKeyType(): int;

    /**
     * Returns which algorithm to be used to create/verify the signature (using OpenSSL constants)
     *
     * @internal
     */
    abstract public function getAlgorithm(): int;
}
