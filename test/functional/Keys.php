<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 */
trait Keys
{
    /**
     * @var array
     */
    protected static $rsaKeys;

    /**
     * @var array
     */
    protected static $ecdsaKeys;

    /**
     * @beforeClass
     */
    public static function createRsaKeys()
    {
        $dir = 'file://' . __DIR__;

        static::$rsaKeys = [
            'private' => new Key($dir . '/rsa/private.key'),
            'public' => new Key($dir . '/rsa/public.key'),
            'encrypted-private' => new Key($dir . '/rsa/encrypted-private.key', 'testing'),
            'encrypted-public' => new Key($dir . '/rsa/encrypted-public.key')
        ];
    }

    /**
     * @beforeClass
     */
    public static function createEcdsaKeys()
    {
        $dir = 'file://' . __DIR__;

        static::$ecdsaKeys = [
            'private' => new Key($dir . '/ecdsa/private.key'),
            'private-params' => new Key($dir . '/ecdsa/private2.key'),
            'public1' => new Key($dir . '/ecdsa/public1.key'),
            'public2' => new Key($dir . '/ecdsa/public2.key'),
            'public-params' => new Key($dir . '/ecdsa/public3.key'),
        ];
    }
}
