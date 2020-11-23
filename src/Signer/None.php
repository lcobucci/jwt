<?php

namespace Lcobucci\JWT\Signer;

final class None extends BaseSigner
{
    public function getAlgorithmId()
    {
        return 'none';
    }

    public function createHash($payload, Key $key)
    {
        return '';
    }

    public function doVerify($expected, $payload, Key $key)
    {
        return $expected === '';
    }
}
