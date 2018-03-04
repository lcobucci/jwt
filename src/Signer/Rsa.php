<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;
use Lcobucci\JWT\Signer;
use const OPENSSL_KEYTYPE_RSA;
use function openssl_error_string;
use function openssl_get_privatekey;
use function openssl_get_publickey;
use function openssl_pkey_get_details;
use function openssl_sign;
use function openssl_verify;

abstract class Rsa implements Signer
{
    /**
     * {@inheritdoc}
     */
    final public function sign(string $payload, Key $key): string
    {
        $key = openssl_get_privatekey($key->getContent(), $key->getPassphrase());
        $this->validateKey($key);

        $signature = '';

        if (! openssl_sign($payload, $signature, $key, $this->getAlgorithm())) {
            throw new InvalidArgumentException(
                'There was an error while creating the signature: ' . openssl_error_string()
            );
        }

        return $signature;
    }

    /**
     * {@inheritdoc}
     */
    final public function verify(string $expected, string $payload, Key $key): bool
    {
        $key = openssl_get_publickey($key->getContent());
        $this->validateKey($key);

        return openssl_verify($payload, $expected, $key, $this->getAlgorithm()) === 1;
    }

    /**
     * Raise an exception when the key type is not the expected type
     *
     * @param resource|bool $key
     *
     * @throws InvalidArgumentException
     */
    private function validateKey($key): void
    {
        if ($key === false) {
            throw new InvalidArgumentException(
                'It was not possible to parse your key, reason: ' . openssl_error_string()
            );
        }

        $details = openssl_pkey_get_details($key);

        if (! isset($details['key']) || $details['type'] !== OPENSSL_KEYTYPE_RSA) {
            throw new InvalidArgumentException('This key is not compatible with RSA signatures');
        }
    }

    abstract public function getAlgorithm(): int;
}
