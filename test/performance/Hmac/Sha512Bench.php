<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Hmac;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;

final class Sha512Bench extends HmacBench
{
    protected function signer(): Signer
    {
        return new Sha512();
    }

    protected function createKey(): Key
    {
        return InMemory::base64Encoded(
            'OgXKIs+aZCQgXnDfi8mAFnWVo+Xn3JTR7BvT/j1Q1zP9oRx9xGg4jmpq00RsPPDclYi8+jRl664pu4d0zan2ow==',
        );
    }
}
