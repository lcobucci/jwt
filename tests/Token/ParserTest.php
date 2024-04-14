<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\InvalidTokenStructure;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Token\UnsupportedHeaderFound;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

#[PHPUnit\CoversClass(Parser::class)]
#[PHPUnit\CoversClass(InvalidTokenStructure::class)]
#[PHPUnit\CoversClass(UnsupportedHeaderFound::class)]
#[PHPUnit\UsesClass(Plain::class)]
#[PHPUnit\UsesClass(DataSet::class)]
#[PHPUnit\UsesClass(Signature::class)]
final class ParserTest extends TestCase
{
    protected Decoder&MockObject $decoder;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->decoder = $this->createMock(Decoder::class);
    }

    private function createParser(): Parser
    {
        return new Parser($this->decoder);
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parse('.');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveHeaders(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Header part');

        $parser->parse('.b.c');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveClaims(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Claim part');

        $parser->parse('a..c');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveSignature(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Signature part');

        $parser->parse('a.b.');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded(): void
    {
        $this->decoder->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('b');

        $this->decoder->method('jsonDecode')
                      ->with('b')
                      ->willThrowException(new RuntimeException('Nope'));

        $parser = $this->createParser();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Nope');

        $parser->parse('a.b.c');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenDealingWithNonArrayHeaders(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenDealingWithHeadersThatHaveEmptyStringKeys(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(UnsupportedHeaderFound::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parse('a.a.a');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenDealingWithNonArrayClaims(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    #[PHPUnit\Test]
    public function parseMustRaiseExceptionWhenDealingWithClaimsThatHaveEmptyStringKeys(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], ['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    #[PHPUnit\Test]
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustConfigureTypeToJWTWhenItIsMissing(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustNotChangeTypeWhenItIsConfigured(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWS', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWS', 'alg' => 'none'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'none']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustReturnASignedTokenWhenSignatureIsInformed(): void
    {
        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', [RegisteredClaims::AUDIENCE => 'test']],
            ]);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    #[PHPUnit\Test]
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => 1486930757.023055,
        ];

        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $token = $this->createParser()->parse('a.b.c');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U', '1486930663'),
            $claims->get(RegisteredClaims::ISSUED_AT),
        );

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.023055'),
            $claims->get(RegisteredClaims::EXPIRATION_TIME),
        );
    }

    #[PHPUnit\Test]
    public function parseMustConvertStringDates(): void
    {
        $data = [RegisteredClaims::NOT_BEFORE => '1486930757.000000'];

        $this->decoder->expects($this->exactly(3))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
                ['c', 'c_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $token = $this->createParser()->parse('a.b.c');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.000000'),
            $claims->get(RegisteredClaims::NOT_BEFORE),
        );
    }

    #[PHPUnit\Test]
    public function parseShouldRaiseExceptionOnInvalidDate(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => '14/10/2018 10:50:10.10 UTC'];

        $this->decoder->expects($this->exactly(2))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('Value is not in the allowed date format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parse('a.b.c');
    }

    #[PHPUnit\Test]
    public function parseShouldRaiseExceptionOnTimestampBeyondDateTimeImmutableRange(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => -10000000000 ** 5];

        $this->decoder->expects($this->exactly(2))
            ->method('base64UrlDecode')
            ->willReturnMap([
                ['a', 'a_dec'],
                ['b', 'b_dec'],
            ]);

        $this->decoder->expects($this->exactly(2))
            ->method('jsonDecode')
            ->willReturnMap([
                ['a_dec', ['typ' => 'JWT', 'alg' => 'HS256']],
                ['b_dec', $data],
            ]);

        $this->expectException(InvalidTokenStructure::class);
        $this->createParser()->parse('a.b.c');
    }
}
