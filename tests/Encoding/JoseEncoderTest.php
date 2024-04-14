<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Encoding;

use Lcobucci\JWT\Encoding\CannotDecodeContent;
use Lcobucci\JWT\Encoding\CannotEncodeContent;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\SodiumBase64Polyfill;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;
use function base64_decode;
use function is_string;

#[PHPUnit\CoversClass(JoseEncoder::class)]
#[PHPUnit\CoversClass(CannotDecodeContent::class)]
#[PHPUnit\CoversClass(CannotEncodeContent::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
final class JoseEncoderTest extends TestCase
{
    #[PHPUnit\Test]
    public function jsonEncodeMustReturnAJSONString(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('{"test":"test"}', $encoder->jsonEncode(['test' => 'test']));
    }

    #[PHPUnit\Test]
    public function jsonEncodeShouldNotEscapeUnicode(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('"汉语"', $encoder->jsonEncode('汉语'));
    }

    #[PHPUnit\Test]
    public function jsonEncodeShouldNotEscapeSlashes(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('"https://google.com"', $encoder->jsonEncode('https://google.com'));
    }

    #[PHPUnit\Test]
    public function jsonEncodeMustRaiseExceptionWhenAnErrorHasOccurred(): void
    {
        $encoder = new JoseEncoder();

        $this->expectException(CannotEncodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while encoding to JSON');

        $encoder->jsonEncode("\xB1\x31");
    }

    #[PHPUnit\Test]
    public function jsonDecodeMustReturnTheDecodedData(): void
    {
        $decoder = new JoseEncoder();

        self::assertSame(
            ['test' => ['test' => []]],
            $decoder->jsonDecode('{"test":{"test":{}}}'),
        );
    }

    #[PHPUnit\Test]
    public function jsonDecodeMustRaiseExceptionWhenAnErrorHasOccurred(): void
    {
        $decoder = new JoseEncoder();

        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while decoding from JSON');

        $decoder->jsonDecode('{"test":\'test\'}');
    }

    #[PHPUnit\Test]
    public function base64UrlEncodeMustReturnAUrlSafeBase64(): void
    {
        $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);
        assert(is_string($data));

        $encoder = new JoseEncoder();
        self::assertSame('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo', $encoder->base64UrlEncode($data));
    }

    #[PHPUnit\Test]
    public function base64UrlEncodeMustEncodeBilboMessageProperly(): void
    {
        /** @link https://tools.ietf.org/html/rfc7520#section-4 */
        $message = 'It’s a dangerous business, Frodo, going out your door. You step '
                   . "onto the road, and if you don't keep your feet, there’s no knowing "
                   . 'where you might be swept off to.';

        $expected = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH'
                    . 'lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk'
                    . 'b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm'
                    . 'UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

        $encoder = new JoseEncoder();
        self::assertSame($expected, $encoder->base64UrlEncode($message));
    }

    #[PHPUnit\Test]
    public function base64UrlDecodeMustRaiseExceptionWhenInvalidBase64CharsAreUsed(): void
    {
        $decoder = new JoseEncoder();

        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

        $decoder->base64UrlDecode('ááá');
    }

    #[PHPUnit\Test]
    public function base64UrlDecodeMustReturnTheRightData(): void
    {
        $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);

        $decoder = new JoseEncoder();
        self::assertSame($data, $decoder->base64UrlDecode('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo'));
    }

    #[PHPUnit\Test]
    public function base64UrlDecodeMustDecodeBilboMessageProperly(): void
    {
        /** @link https://tools.ietf.org/html/rfc7520#section-4 */
        $message = 'SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH'
                   . 'lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk'
                   . 'b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm'
                   . 'UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4';

        $expected = 'It’s a dangerous business, Frodo, going out your door. You step '
                    . "onto the road, and if you don't keep your feet, there’s no knowing "
                    . 'where you might be swept off to.';

        $encoder = new JoseEncoder();
        self::assertSame($expected, $encoder->base64UrlDecode($message));
    }
}
