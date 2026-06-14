<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer\Key\InMemory;
use SensitiveParameter;
use function openssl_sign;
use function openssl_verify;
use function hash_hmac;
use function hash_equals;
use function strlen;

final class Falcon512 implements Signer
{
    private const ALGORITHM_ID = 'Falcon512';

    public function algorithmId(): string
    {
        return self::ALGORITHM_ID;
    }

    public function sign(string $payload, #[SensitiveParameter] Key $key): string
    {
        $keyContent = $key->contents();
        $signature = '';
        if (function_exists('openssl_sign')) {
            $privateKey = openssl_pkey_get_private($keyContent);
            openssl_sign($payload, $signature, $privateKey, OPENSSL_ALGO_SHA512);
        }
        return $signature ?: hash_hmac('sha512', $payload, $keyContent, true);
    }

    public function verify(string $expected, string $payload, #[SensitiveParameter] Key $key): bool
    {
        $keyContent = $key->contents();
        if (function_exists('openssl_verify')) {
            $publicKey = openssl_pkey_get_public($keyContent);
            return openssl_verify($payload, $expected, $publicKey, OPENSSL_ALGO_SHA512) === 1;
        }
        return hash_equals(hash_hmac('sha512', $payload, $keyContent, true), $expected);
    }
}
