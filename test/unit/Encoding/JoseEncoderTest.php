<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Encoding;

use PHPUnit\Framework\TestCase;

use function assert;
use function base64_decode;
use function is_string;

/**
 * @covers \Lcobucci\JWT\Encoding\CannotDecodeContent
 * @covers \Lcobucci\JWT\Encoding\CannotEncodeContent
 * @coversDefaultClass \Lcobucci\JWT\Encoding\JoseEncoder
 */
final class JoseEncoderTest extends TestCase
{
    /**
     * @test
     *
     * @covers ::jsonEncode
     */
    public function jsonEncodeMustReturnAJSONString(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('{"test":"test"}', $encoder->jsonEncode(['test' => 'test']));
    }

    /**
     * @test
     *
     * @covers ::jsonEncode
     */
    public function jsonEncodeShouldNotEscapeUnicode(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('"汉语"', $encoder->jsonEncode('汉语'));
    }

    /**
     * @test
     *
     * @covers ::jsonEncode
     */
    public function jsonEncodeShouldNotEscapeSlashes(): void
    {
        $encoder = new JoseEncoder();

        self::assertSame('"http://google.com"', $encoder->jsonEncode('http://google.com'));
    }

    /**
     * @test
     *
     * @covers ::jsonEncode
     */
    public function jsonEncodeMustRaiseExceptionWhenAnErrorHasOccurred(): void
    {
        $encoder = new JoseEncoder();

        $this->expectException(CannotEncodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while encoding to JSON');

        $encoder->jsonEncode("\xB1\x31");
    }

    /**
     * @test
     *
     * @covers ::jsonDecode
     */
    public function jsonDecodeMustReturnTheDecodedData(): void
    {
        $decoder = new JoseEncoder();

        self::assertSame(
            ['test' => ['test' => []]],
            $decoder->jsonDecode('{"test":{"test":{}}}')
        );
    }

    /**
     * @test
     *
     * @covers ::jsonDecode
     */
    public function jsonDecodeMustRaiseExceptionWhenAnErrorHasOccurred(): void
    {
        $decoder = new JoseEncoder();

        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while decoding from JSON');

        $decoder->jsonDecode('{"test":\'test\'}');
    }

    /**
     * @test
     *
     * @covers ::base64UrlEncode
     */
    public function base64UrlEncodeMustReturnAUrlSafeBase64(): void
    {
        $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);
        assert(is_string($data));

        $encoder = new JoseEncoder();
        self::assertSame('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo', $encoder->base64UrlEncode($data));
    }

    /**
     * @link https://tools.ietf.org/html/rfc7520#section-4
     *
     * @test
     *
     * @covers ::base64UrlEncode
     */
    public function base64UrlEncodeMustEncodeBilboMessageProperly(): void
    {
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

    /**
     * @test
     *
     * @covers ::base64UrlDecode
     */
    public function base64UrlDecodeMustRaiseExceptionWhenInvalidBase64CharsAreUsed(): void
    {
        $decoder = new JoseEncoder();

        $this->expectException(CannotDecodeContent::class);
        $this->expectExceptionCode(0);
        $this->expectExceptionMessage('Error while decoding from Base64Url, invalid base64 characters detected');

        $decoder->base64UrlDecode('áááááá');
    }

    /**
     * @test
     *
     * @covers ::base64UrlDecode
     */
    public function base64UrlDecodeMustReturnTheRightData(): void
    {
        $data = base64_decode('0MB2wKB+L3yvIdzeggmJ+5WOSLaRLTUPXbpzqUe0yuo=', true);

        $decoder = new JoseEncoder();
        self::assertSame($data, $decoder->base64UrlDecode('0MB2wKB-L3yvIdzeggmJ-5WOSLaRLTUPXbpzqUe0yuo'));
    }

    /**
     * @link https://tools.ietf.org/html/rfc7520#section-4
     *
     * @test
     *
     * @covers ::base64UrlDecode
     */
    public function base64UrlDecodeMustDecodeBilboMessageProperly(): void
    {
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
