<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\FunctionalTests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\CheckForDeprecations;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Key\LocalFileReference;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use ReflectionProperty;
use function file_put_contents;
use function sys_get_temp_dir;
use function tempnam;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 *
 * @covers \Lcobucci\JWT\Token\DataSet
 */
class HmacTokenTest extends \PHPUnit\Framework\TestCase
{
    use CheckForDeprecations;

    /**
     * @var Sha256
     */
    private $signer;

    /**
     * @before
     */
    public function createSigner()
    {
        $this->signer = new Sha256();
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function builderCanGenerateAToken()
    {
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');
        $this->expectDeprecation('Not specifying the signer and key to Builder#getToken() is deprecated. Please move the arguments from Builder#sign() to Builder#getToken().');

        $user = (object) ['name' => 'testing', 'email' => 'testing@abc.com'];

        $token = (new Builder())->setId(1)
                              ->setAudience('http://client.abc.com')
                              ->setIssuer('http://api.abc.com')
                              ->set('user', $user)
                              ->setHeader('jki', '1234')
                              ->sign($this->signer, 'testing')
                              ->getToken();

        $this->assertAttributeInstanceOf(Signature::class, 'signature', $token);
        $this->assertEquals('1234', $token->getHeader('jki'));
        $this->assertEquals('http://client.abc.com', $token->getClaim('aud'));
        $this->assertEquals('http://api.abc.com', $token->getClaim('iss'));
        $this->assertEquals($user, $token->getClaim('user'));

        return $token;
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Parsing\Decoder
     */
    public function parserCanReadAToken(Token $generated)
    {
        $read = (new Parser())->parse((string) $generated);

        $this->assertEquals($generated, $read);
        $this->assertEquals('testing', $read->getClaim('user')->name);
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnFalseWhenKeyIsNotRight(Token $token)
    {
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');

        $this->assertFalse($token->verify($this->signer, 'testing1'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Lcobucci\JWT\Signer\Hmac\Sha512
     */
    public function verifyShouldReturnFalseWhenAlgorithmIsDifferent(Token $token)
    {
        $this->assertFalse($token->verify(new Sha512(), 'testing'));
    }

    /**
     * @test
     *
     * @depends builderCanGenerateAToken
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function verifyShouldReturnTrueWhenKeyIsRight(Token $token)
    {
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');

        $this->assertTrue($token->verify($this->signer, 'testing'));
    }

    /**
     * @test
     *
     * @covers Lcobucci\JWT\Builder
     * @covers Lcobucci\JWT\Parser
     * @covers Lcobucci\JWT\Token
     * @covers Lcobucci\JWT\Signature
     * @covers Lcobucci\JWT\Signer\Key
     * @covers Lcobucci\JWT\Signer\BaseSigner
     * @covers Lcobucci\JWT\Signer\Hmac
     * @covers Lcobucci\JWT\Signer\Hmac\Sha256
     * @covers Lcobucci\JWT\Claim\Factory
     * @covers Lcobucci\JWT\Claim\Basic
     * @covers Lcobucci\JWT\Parsing\Encoder
     * @covers Lcobucci\JWT\Parsing\Decoder
     */
    public function everythingShouldWorkWhenUsingATokenGeneratedByOtherLibs()
    {
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');

        $data = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJoZWxsbyI6IndvcmxkIn0.Rh'
                . '7AEgqCB7zae1PkgIlvOpeyw9Ab8NGTbeOH7heHO0o';

        $token = (new Parser())->parse((string) $data);

        $this->assertEquals('world', $token->getClaim('hello'));
        $this->assertTrue($token->verify($this->signer, 'testing'));
    }

    /**
     * @test
     *
     * @coversNothing
     *
     * @see \Lcobucci\JWT\Signer\Key::setContent()
     */
    public function signatureValidationWithLocalFileKeyReferenceWillOperateWithKeyContents()
    {
        $key = tempnam(sys_get_temp_dir(), 'key');
        file_put_contents($key, 'just a dummy key');

        $validKey   = LocalFileReference::file($key);
        $invalidKey = InMemory::plainText($key);
        $signer     = new Sha256();

        // 3.4.x implicitly extracts key contents, when `file://` is detected
        $reflectionContents = new ReflectionProperty(InMemory::class, 'content');
        $reflectionContents->setAccessible(true);
        $reflectionContents->setValue($invalidKey, 'file://' . $key);

        $token = (new Builder())
            ->withClaim('foo', 'bar')
            ->getToken($signer, $validKey);

        self::assertFalse(
            $token->verify($signer, $invalidKey),
            'Token cannot be validated against the **path** of the key'
        );
        self::assertTrue(
            $token->verify($signer, $validKey),
            'Token can be validated against the **contents** of the key'
        );
    }
}
