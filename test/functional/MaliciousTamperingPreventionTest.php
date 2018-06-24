<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\Jose\Parsing\Parser;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use PHPUnit\Framework\TestCase;
use const PHP_EOL;
use function explode;
use function hash_hmac;
use function implode;

final class MaliciousTamperingPreventionTest extends TestCase
{
    use Keys;

    /**
     * @var Configuration
     */
    private $config;

    /**
     * @before
     */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forAsymmetricSigner(
            ES512::create(),
            new Key('my-private-key'),
            new Key(
                '-----BEGIN PUBLIC KEY-----' . PHP_EOL
                . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
                . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
                . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
                . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
                . '-----END PUBLIC KEY-----'
            )
        );
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Token\Builder
     * @covers \Lcobucci\JWT\Token\Parser
     * @covers \Lcobucci\JWT\Token\Plain
     * @covers \Lcobucci\JWT\Token\DataSet
     * @covers \Lcobucci\JWT\Token\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Asn1
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha512
     * @covers \Lcobucci\JWT\Validation\Constraint\SignedWith
     * @covers \Lcobucci\JWT\Validation\Validator
     */
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

        /** @var Plain $token */
        $token = $this->config->getParser()->parse($bad);

        self::assertEquals('world', $token->claims()->get('hello'), 'The claim content should not be modified');

        $validator = $this->config->getValidator();

        self::assertFalse(
            $validator->validate($token, new SignedWith(new HS512(), $this->config->getVerificationKey())),
            'Using the attackers signer should make things unsafe'
        );

        self::assertFalse(
            $validator->validate(
                $token,
                new SignedWith(
                    $this->config->getSigner(),
                    $this->config->getVerificationKey()
                )
            ),
            'But we know which Signer should be used so the attack fails'
        );
    }

    private function createMaliciousToken(string $token): string
    {
        $dec     = new Parser();
        $asplode = explode('.', $token);

        // The user is lying; we insist that we're using HMAC-SHA512, with the
        // public key as the HMAC secret key. This just builds a forged message:
        $asplode[0] = $dec->base64UrlEncode('{"alg":"HS512","typ":"JWT"}');

        $hmac = hash_hmac(
            'sha512',
            $asplode[0] . '.' . $asplode[1],
            $this->config->getVerificationKey()->getContent(),
            true
        );

        $asplode[2] = $dec->base64UrlEncode($hmac);

        return implode('.', $asplode);
    }
}
