<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;

trait Keys
{
    /** @var array<string, Key> */
    protected static array $rsaKeys;

    /** @var array<string, Key> */
    protected static array $ecdsaKeys;

    /** @var array<string, Key> */
    protected static array $eddsaKeys;

    /** @beforeClass */
    public static function createRsaKeys(): void
    {
        static::$rsaKeys = [
            'private'           => Key\InMemory::file(__DIR__ . '/rsa/private.key'),
            'public'            => Key\InMemory::file(__DIR__ . '/rsa/public.key'),
            'encrypted-private' => Key\InMemory::file(__DIR__ . '/rsa/encrypted-private.key', 'testing'),
            'encrypted-public'  => Key\InMemory::file(__DIR__ . '/rsa/encrypted-public.key'),
            'private_short'     => Key\InMemory::file(__DIR__ . '/rsa/private_512.key'),
            'public_short'      => Key\InMemory::file(__DIR__ . '/rsa/public_512.key'),
        ];
    }

    /** @beforeClass */
    public static function createEcdsaKeys(): void
    {
        static::$ecdsaKeys = [
            'private'        => Key\InMemory::file(__DIR__ . '/ecdsa/private.key'),
            'private-params' => Key\InMemory::file(__DIR__ . '/ecdsa/private2.key'),
            'public1'        => Key\InMemory::file(__DIR__ . '/ecdsa/public1.key'),
            'public2'        => Key\InMemory::file(__DIR__ . '/ecdsa/public2.key'),
            'public-params'  => Key\InMemory::file(__DIR__ . '/ecdsa/public3.key'),
            'private_ec512'  => Key\InMemory::file(__DIR__ . '/ecdsa/private_ec512.key'),
            'public_ec512'   => Key\InMemory::file(__DIR__ . '/ecdsa/public_ec512.key'),
            'public2_ec512'  => Key\InMemory::file(__DIR__ . '/ecdsa/public2_ec512.key'),
            'private_short'  => Key\InMemory::file(__DIR__ . '/ecdsa/private_ec160.key'),
            'public_short'   => Key\InMemory::file(__DIR__ . '/ecdsa/public_ec160.key'),
        ];
    }

    /** @beforeClass */
    public static function createEddsaKeys(): void
    {
        static::$eddsaKeys = [
            'private' => Key\InMemory::base64Encoded(
                'K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg=='
            ),
            'public1' => Key\InMemory::base64Encoded('R0TLf2hkQaCg/z7eR/4mIBgpWu0NOAnYzlKS0q42YbY='),
            'public2' => Key\InMemory::base64Encoded('8uLLzCdMrIWcOrAxS/fteYyJhWIGH+wav2fNz8NZhvI='),
        ];
    }
}
