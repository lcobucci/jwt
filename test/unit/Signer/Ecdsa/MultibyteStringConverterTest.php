<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

use function bin2hex;
use function hex2bin;
use function strlen;

/** @coversDefaultClass \Lcobucci\JWT\Signer\Ecdsa\MultibyteStringConverter */
final class MultibyteStringConverterTest extends TestCase
{
    /**
     * @test
     * @dataProvider pointsConversionData
     *
     * @covers ::toAsn1
     * @covers ::octetLength
     * @covers ::preparePositiveInteger
     *
     * @param non-empty-string $r
     * @param non-empty-string $s
     * @param non-empty-string $asn1
     */
    public function toAsn1ShouldReturnThePointsInAnAsn1SequenceFormat(
        string $r,
        string $s,
        string $asn1,
    ): void {
        $converter = new MultibyteStringConverter();
        $message   = hex2bin($r . $s);
        self::assertIsString($message);
        self::assertNotSame('', $message);

        self::assertSame($asn1, bin2hex($converter->toAsn1($message, strlen($r))));
    }

    /**
     * @test
     *
     * @covers ::toAsn1
     * @covers ::octetLength
     * @covers \Lcobucci\JWT\Signer\Ecdsa\ConversionFailed
     */
    public function toAsn1ShouldRaiseExceptionWhenPointsDoNotHaveCorrectLength(): void
    {
        $converter = new MultibyteStringConverter();

        $this->expectException(ConversionFailed::class);
        $this->expectExceptionMessage('Invalid signature length');
        $converter->toAsn1('a very wrong string', 64);
    }

    /**
     * @test
     * @dataProvider pointsConversionData
     *
     * @covers ::fromAsn1
     * @covers ::readAsn1Content
     * @covers ::readAsn1Integer
     * @covers ::retrievePositiveInteger
     */
    public function fromAsn1ShouldReturnTheConcatenatedPoints(string $r, string $s, string $asn1): void
    {
        $converter = new MultibyteStringConverter();
        $message   = hex2bin($asn1);
        self::assertIsString($message);
        self::assertNotSame('', $message);

        self::assertSame($r . $s, bin2hex($converter->fromAsn1($message, strlen($r))));
    }

    /** @return string[][] */
    public function pointsConversionData(): iterable
    {
        return [
            [
                'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
                'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
                '3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7'
                . 'a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
            ],
            [
                '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
                '99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8',
                '306602310094edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fa'
                . 'be4602310099ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38'
                . '628ac8',
            ],
            [
                '00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7'
                . 'd4e8455cc91f9b15bf05ec36e377fa',
                '00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20'
                . 'f8ccb1dccc43997f1ee0e44da4a67a',
                '308187024200c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add15'
                . '2b534931d7d4e8455cc91f9b15bf05ec36e377fa0241617cce7cf5064806c467f678d3b4080d6f1cc50af26ca20941730828'
                . '1b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a',
            ],
        ];
    }

    /**
     * @test
     * @dataProvider invalidAsn1Structures
     *
     * @covers ::fromAsn1
     * @covers ::readAsn1Content
     * @covers ::readAsn1Integer
     * @covers ::retrievePositiveInteger
     * @covers \Lcobucci\JWT\Signer\Ecdsa\ConversionFailed
     */
    public function fromAsn1ShouldRaiseExceptionOnInvalidMessage(string $message, string $expectedMessage): void
    {
        $converter = new MultibyteStringConverter();
        $message   = hex2bin($message);
        self::assertIsString($message);

        $this->expectException(ConversionFailed::class);
        $this->expectExceptionMessage($expectedMessage);
        $converter->fromAsn1($message, 64);
    }

    /** @return string[][] */
    public function invalidAsn1Structures(): iterable
    {
        return [
            'Not a sequence'           => ['', 'Should start with a sequence'],
            'Sequence without length'  => ['30', 'Should contain an integer'],
            'Only one string element'  => ['3006030204f0', 'Should contain an integer'],
            'Only one integer element' => ['3004020101', 'Should contain an integer'],
            'Integer+string elements'  => ['300a020101030204f0', 'Should contain an integer'],
        ];
    }
}
