<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use Lcobucci\JWT\Signer\Ecdsa;

use const OPENSSL_ALGO_SHA256;

/**
 * ECDSA using the secp256k1 curve and SHA-256, as defined by RFC 8812.
 *
 * @see https://www.rfc-editor.org/rfc/rfc8812#section-3.2
 */
final readonly class Sha256K extends Ecdsa
{
    public function algorithmId(): string
    {
        return 'ES256K';
    }

    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    public function pointLength(): int
    {
        return 64;
    }

    public function expectedKeyLength(): int
    {
        return 256;
    }

    public function expectedCurve(): string
    {
        return 'secp256k1';
    }
}
