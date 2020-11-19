<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\LocalFileReference;

trait Keys
{
    /** @var array<string, Key> */
    protected static array $rsaKeys;

    /** @var array<string, Key> */
    protected static array $ecdsaKeys;

    /** @beforeClass */
    public static function createRsaKeys(): void
    {
        static::$rsaKeys = [
            'private'           => LocalFileReference::file(__DIR__ . '/rsa/private.key'),
            'public'            => LocalFileReference::file(__DIR__ . '/rsa/public.key'),
            'encrypted-private' => LocalFileReference::file(__DIR__ . '/rsa/encrypted-private.key', 'testing'),
            'encrypted-public'  => LocalFileReference::file(__DIR__ . '/rsa/encrypted-public.key'),
        ];
    }

    /** @beforeClass */
    public static function createEcdsaKeys(): void
    {
        static::$ecdsaKeys = [
            'private'        => LocalFileReference::file(__DIR__ . '/ecdsa/private.key'),
            'private-params' => LocalFileReference::file(__DIR__ . '/ecdsa/private2.key'),
            'public1'        => LocalFileReference::file(__DIR__ . '/ecdsa/public1.key'),
            'public2'        => LocalFileReference::file(__DIR__ . '/ecdsa/public2.key'),
            'public-params'  => LocalFileReference::file(__DIR__ . '/ecdsa/public3.key'),
            'private_ec512'  => LocalFileReference::file(__DIR__ . '/ecdsa/private_ec512.key'),
            'public_ec512'   => LocalFileReference::file(__DIR__ . '/ecdsa/public_ec512.key'),
            'public2_ec512'  => LocalFileReference::file(__DIR__ . '/ecdsa/public2_ec512.key'),
        ];
    }
}
