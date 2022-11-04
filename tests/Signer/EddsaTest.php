<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Tests\Keys;
use PHPUnit\Framework\TestCase;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Eddsa */
final class EddsaTest extends TestCase
{
    use Keys;

    /**
     * @test
     *
     * @covers ::algorithmId
     */
    public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame('EdDSA', (new Eddsa())->algorithmId());
    }

    /**
     * @test
     *
     * @covers ::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldReturnAValidEddsaSignature(): void
    {
        $payload = 'testing';

        $signer    = new Eddsa();
        $signature = $signer->sign($payload, self::$eddsaKeys['private']);

        $publicKey = self::$eddsaKeys['public1']->contents();

        self::assertTrue(sodium_crypto_sign_verify_detached($signature, $payload, $publicKey));
    }

    /**
     * @test
     *
     * @covers ::sign
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function signShouldRaiseAnExceptionWhenKeyIsInvalid(): void
    {
        $signer = new Eddsa();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $signer->sign('testing', InMemory::plainText('tooshort'));
    }

    /**
     * @test
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload   = 'testing';
        $signature = sodium_crypto_sign_detached($payload, self::$eddsaKeys['private']->contents());

        $signer = new Eddsa();

        self::assertTrue($signer->verify($signature, $payload, self::$eddsaKeys['public1']));
    }

    /**
     * @test
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = new Eddsa();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_BYTES');

        $signer->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.4
     *
     * @test
     *
     * @covers ::sign
     *
     * @uses \Lcobucci\JWT\Encoding\JoseEncoder
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::base642bin()
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::bin2base64()
     */
    public function signatureOfRfcExample(): void
    {
        $signer  = new Eddsa();
        $encoder = new JoseEncoder();

        $decoded = $encoder->base64UrlDecode('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A');
        self::assertNotSame('', $decoded);
        $key       = InMemory::plainText(
            $decoded
            . $encoder->base64UrlDecode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo'),
        );
        $payload   = $encoder->base64UrlEncode('{"alg":"EdDSA"}')
            . '.'
            . $encoder->base64UrlEncode('Example of Ed25519 signing');
        $signature = $signer->sign($payload, $key);

        self::assertSame('eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc', $payload);
        self::assertSame(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
            $encoder->base64UrlEncode($signature),
        );
    }

    /**
     * @see https://tools.ietf.org/html/rfc8037#appendix-A.5
     *
     * @test
     *
     * @covers ::verify
     *
     * @uses \Lcobucci\JWT\Encoding\JoseEncoder
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     * @uses \Lcobucci\JWT\SodiumBase64Polyfill::base642bin()
     */
    public function verificationOfRfcExample(): void
    {
        $signer  = new Eddsa();
        $encoder = new JoseEncoder();

        $decoded = $encoder->base64UrlDecode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');
        self::assertNotSame('', $decoded);

        $key       = InMemory::plainText($decoded);
        $payload   = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = $encoder->base64UrlDecode(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
        );

        self::assertTrue($signer->verify($signature, $payload, $key));
    }
}
