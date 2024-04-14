<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Signer;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\InvalidKeyProvided;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Tests\Keys;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_verify_detached;

#[PHPUnit\CoversClass(Eddsa::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(JoseEncoder::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
final class EddsaTest extends TestCase
{
    use Keys;

    #[PHPUnit\Test]
    public function algorithmIdMustBeCorrect(): void
    {
        self::assertSame('EdDSA', (new Eddsa())->algorithmId());
    }

    #[PHPUnit\Test]
    public function signShouldReturnAValidEddsaSignature(): void
    {
        $payload = 'testing';

        $signer    = new Eddsa();
        $signature = $signer->sign($payload, self::$eddsaKeys['private']);

        $publicKey = self::$eddsaKeys['public1']->contents();

        self::assertTrue(sodium_crypto_sign_verify_detached($signature, $payload, $publicKey));
    }

    #[PHPUnit\Test]
    public function signShouldRaiseAnExceptionWhenKeyIsInvalid(): void
    {
        $signer = new Eddsa();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_SECRETKEYBYTES');

        $signer->sign('testing', InMemory::plainText('tooshort'));
    }

    #[PHPUnit\Test]
    public function verifyShouldReturnTrueWhenSignatureIsValid(): void
    {
        $payload   = 'testing';
        $signature = sodium_crypto_sign_detached($payload, self::$eddsaKeys['private']->contents());
        $signer    = new Eddsa();

        self::assertTrue($signer->verify($signature, $payload, self::$eddsaKeys['public1']));
    }

    #[PHPUnit\Test]
    public function verifyShouldRaiseAnExceptionWhenKeyIsNotParseable(): void
    {
        $signer = new Eddsa();

        $this->expectException(InvalidKeyProvided::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('SODIUM_CRYPTO_SIGN_BYTES');

        $signer->verify('testing', 'testing', InMemory::plainText('blablabla'));
    }

    /** @see https://tools.ietf.org/html/rfc8037#appendix-A.4 */
    #[PHPUnit\Test]
    public function signatureOfRfcExample(): void
    {
        $signer  = new Eddsa();
        $encoder = new JoseEncoder();

        $decoded   = $encoder->base64UrlDecode('nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A');
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

    /** @see https://tools.ietf.org/html/rfc8037#appendix-A.5 */
    #[PHPUnit\Test]
    public function verificationOfRfcExample(): void
    {
        $signer  = new Eddsa();
        $encoder = new JoseEncoder();

        $decoded = $encoder->base64UrlDecode('11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');

        $key       = InMemory::plainText($decoded);
        $payload   = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = $encoder->base64UrlDecode(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg',
        );

        self::assertTrue($signer->verify($signature, $payload, $key));
    }
}
