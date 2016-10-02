<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Keys;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer\Ecdsa\Sha256;
use Lcobucci\JWT\Signer\Ecdsa\Sha512;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\Jose\Parsing\Parser;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
class EcdsaTokenTest extends \PHPUnit_Framework_TestCase
{
    use Keys;

    /**
     * @var Configuration
     */
    private $config;

    /**
     * @before
     */
    public function createConfiguration()
    {
        $this->config = new Configuration();
        $this->config->setSigner(Sha256::create());
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsInvalid()
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->canOnlyBeUsedBy('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->with('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->sign($this->config->getSigner(), new Key('testing'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function builderShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible()
    {
        $builder = $this->config->createBuilder();

        $builder->identifiedBy('1')
                ->canOnlyBeUsedBy('http://client.abc.com')
                ->issuedBy('http://api.abc.com')
                ->with('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                ->sign($this->config->getSigner(), static::$rsaKeys['private']);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $user = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->createBuilder();

        $token = $builder->identifiedBy('1')
                         ->canOnlyBeUsedBy('http://client.abc.com')
                         ->canOnlyBeUsedBy('http://client2.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->with('user', $user)
                         ->withHeader('jki', '1234')
                         ->sign($this->config->getSigner(), static::$ecdsaKeys['private'])
                         ->getToken();

        self::assertAttributeInstanceOf(Signature::class, 'signature', $token);
        self::assertEquals('1234', $token->getHeader('jki'));
        self::assertEquals(['http://client.abc.com', 'http://client2.abc.com'], $token->getClaim('aud'));
        self::assertEquals('http://api.abc.com', $token->getClaim('iss'));
        self::assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = $this->config->getParser()->parse((string) $generated);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->getClaim('user')['name']);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        self::assertFalse($token->verify($this->config->getSigner(), static::$ecdsaKeys['public2']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        self::assertFalse($token->verify(Sha512::create(), static::$ecdsaKeys['public1']));
    }

    /**
     * @test
     *
     * @expectedException \RuntimeException
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function verifyShouldRaiseExceptionWhenKeyIsNotEcdsaCompatible(Token $token)
    {
        self::assertFalse($token->verify($this->config->getSigner(), static::$rsaKeys['public']));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        self::assertTrue($token->verify($this->config->getSigner(), static::$ecdsaKeys['public1']));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha256
     */
    public function everythingShouldWorkWithAKeyWithParams()
    {
        $builder = $this->config->createBuilder();
        $signer = $this->config->getSigner();

        $token = $builder->identifiedBy('1')
                         ->canOnlyBeUsedBy('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->with('user', ['name' => 'testing', 'email' => 'testing@abc.com'])
                         ->withHeader('jki', '1234')
                         ->sign($signer, static::$ecdsaKeys['private-params'])
                         ->getToken();

        self::assertTrue($token->verify($signer, static::$ecdsaKeys['public-params']));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
                . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
                . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
                . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        $key = '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
               . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
               . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
               . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
               . '-----END PUBLIC KEY-----';

        $key = new Key($key);
        $token = $this->config->getParser()->parse((string) $data);

        self::assertEquals('world', $token->getClaim('hello'));
        self::assertTrue($token->verify(Sha512::create(), $key));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration
     * @covers \Lcobucci\JWT\Builder
     * @covers \Lcobucci\JWT\Parser
     * @covers \Lcobucci\JWT\Token
     * @covers \Lcobucci\JWT\Signature
     * @covers \Lcobucci\JWT\Signer\Key
     * @covers \Lcobucci\JWT\Signer\Ecdsa
     * @covers \Lcobucci\JWT\Signer\Ecdsa\KeyParser
     * @covers \Lcobucci\JWT\Signer\Ecdsa\EccAdapter
     * @covers \Lcobucci\JWT\Signer\Ecdsa\SignatureSerializer
     * @covers \Lcobucci\JWT\Signer\Ecdsa\Sha512
     * @covers \Lcobucci\JWT\Signer\Hmac
     * @covers \Lcobucci\JWT\Signer\Hmac\Sha512
     * @covers \Lcobucci\JWT\Claim\Factory
     * @covers \Lcobucci\JWT\Claim\Basic
     */
    public function preventRegressionsThatAllowsMaliciousTampering()
    {
        $data = 'eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0.'
                . 'AQx1MqdTni6KuzfOoedg2-7NUiwe-b88SWbdmviz40GTwrM0Mybp1i1tVtm'
                . 'TSQ91oEXGXBdtwsN6yalzP9J-sp2YATX_Tv4h-BednbdSvYxZsYnUoZ--ZU'
                . 'dL10t7g8Yt3y9hdY_diOjIptcha6ajX8yzkDGYG42iSe3f5LywSuD6FO5c';

        $key = new Key(
            '-----BEGIN PUBLIC KEY-----' . PHP_EOL
            . 'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAcpkss6wI7PPlxj3t7A1RqMH3nvL4' . PHP_EOL
            . 'L5Tzxze/XeeYZnHqxiX+gle70DlGRMqqOq+PJ6RYX7vK0PJFdiAIXlyPQq0B3KaU' . PHP_EOL
            . 'e86IvFeQSFrJdCc0K8NfiH2G1loIk3fiR+YLqlXk6FAeKtpXJKxR1pCQCAM+vBCs' . PHP_EOL
            . 'mZudf1zCUZ8/4eodlHU=' . PHP_EOL
            . '-----END PUBLIC KEY-----'
        );

        // Let's let the attacker tamper with our message!
        $bad = $this->createMaliciousToken($data, $key);

        /**
         * At this point, we have our forged message in $bad for testing...
         *
         * Now, if we allow the attacker to dictate what Signer we use
         * (e.g. HMAC-SHA512 instead of ECDSA), they can forge messages!
         */
        $token = $this->config->getParser()->parse((string) $bad);

        self::assertEquals('world', $token->getClaim('hello'), 'The claim content should not be modified');
        self::assertTrue($token->verify(new HS512(), $key), 'Using the attackers signer should make things unsafe');

        self::assertFalse(
            $token->verify(Sha512::create(), $key),
            'But we know which Signer should be used so the attack fails'
        );
    }

    /**
     * @ref https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/
     *
     * @param string $token
     * @param Key $key
     *
     * @return string
     */
    private function createMaliciousToken(string $token, Key $key): string
    {
        $dec = new Parser();
        $asplode = explode('.', $token);

        // The user is lying; we insist that we're using HMAC-SHA512, with the
        // public key as the HMAC secret key. This just builds a forged message:
        $asplode[0] = $dec->base64UrlEncode('{"alg":"HS512","typ":"JWT"}');

        $hmac = hash_hmac(
            'sha512',
            $asplode[0] . '.' . $asplode[1],
            $key->getContent(),
            true
        );

        $asplode[2] = $dec->base64UrlEncode($hmac);

        return implode('.', $asplode);
    }
}
