<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;
use function explode;
use function hash_hmac;
use function implode;

use const PHP_EOL;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\CoversClass(Encoding\JoseEncoder::class)]
#[PHPUnit\CoversClass(Token\Parser::class)]
#[PHPUnit\CoversClass(Token\Plain::class)]
#[PHPUnit\CoversClass(Token\DataSet::class)]
#[PHPUnit\CoversClass(Token\Signature::class)]
#[PHPUnit\CoversClass(Ecdsa::class)]
#[PHPUnit\CoversClass(Ecdsa\Sha512::class)]
#[PHPUnit\CoversClass(Hmac\Sha256::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
final class MaliciousTamperingPreventionTest extends TestCase
{
    use Keys;

    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            new ES512(),
            InMemory::plainText('my-private-key'),
            InMemory::plainText(
                '-----BEGIN PUBLIC KEY-----' . PHP_EOL
                . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
                . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
                . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
                . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
                . '-----END PUBLIC KEY-----',
            ),
        );
    }

    #[PHPUnit\Test]
    public function preventRegressionsThatAllowsMaliciousTampering(): void
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
            . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
            . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
            . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        // Let's let the attacker tamper with our message!
        $bad = $this->createMaliciousToken($data);

        /**
         * At this point, we have our forged message in $bad for testing...
         *
         * Now, if we allow the attacker to dictate what Signer we use
         * (e.g. HMAC-SHA512 instead of ECDSA), they can forge messages!
         */

        $token = $this->config->parser()->parse($bad);
        assert($token instanceof Plain);

        self::assertSame('world', $token->claims()->get('hello'), 'The claim content should not be modified');

        $validator = $this->config->validator();

        self::assertFalse(
            $validator->validate($token, new SignedWith(new HS512(), $this->config->verificationKey())),
            'Using the attackers signer should make things unsafe',
        );

        self::assertFalse(
            $validator->validate(
                $token,
                new SignedWith(
                    $this->config->signer(),
                    $this->config->verificationKey(),
                ),
            ),
            'But we know which Signer should be used so the attack fails',
        );
    }

    /** @return non-empty-string */
    private function createMaliciousToken(string $token): string
    {
        $dec     = new JoseEncoder();
        $asplode = explode('.', $token);

        // The user is lying; we insist that we're using HMAC-SHA512, with the
        // public key as the HMAC secret key. This just builds a forged message:
        $asplode[0] = $dec->base64UrlEncode('{"alg":"HS512","typ":"JWT"}');

        $hmac = hash_hmac(
            'sha512',
            $asplode[0] . '.' . $asplode[1],
            $this->config->verificationKey()->contents(),
            true,
        );

        $asplode[2] = $dec->base64UrlEncode($hmac);

        return implode('.', $asplode);
    }
}
