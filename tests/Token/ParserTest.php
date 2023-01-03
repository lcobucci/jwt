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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * @covers \Lcobucci\JWT\Token\Parser
 * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
 * @covers \Lcobucci\JWT\Token\UnsupportedHeaderFound
 *
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 * @uses \Lcobucci\JWT\Token\DataSet
 */
final class ParserTest extends TestCase
{
    /** @var Decoder&MockObject */
    protected Decoder $decoder;

    /** @before */
    public function createDependencies(): void
    {
        $this->decoder = $this->createMock(Decoder::class);
    }

    private function createParser(): Parser
    {
        return new Parser($this->decoder);
    }

    /** @test */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parse('.');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveHeaders(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Header part');

        $parser->parse('.b.c');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveClaims(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Claim part');

        $parser->parse('a..c');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveSignature(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string is missing the Signature part');

        $parser->parse('a.b.');
    }

    /** @test */
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

    /** @test */
    public function parseMustRaiseExceptionWhenDealingWithNonArrayHeaders(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenDealingWithHeadersThatHaveEmptyStringKeys(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.a');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(UnsupportedHeaderFound::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parse('a.a.a');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenDealingWithNonArrayClaims(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    /** @test */
    public function parseMustRaiseExceptionWhenDealingWithClaimsThatHaveEmptyStringKeys(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], ['' => 'foo']);

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.a');
    }

    /** @test */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects(self::exactly(3))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'], ['c'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWT', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test'],
                      );

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

    /** @test */
    public function parseMustConfigureTypeToJWTWhenItIsMissing(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test'],
                      );

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

    /** @test */
    public function parseMustNotChangeTypeWhenItIsConfigured(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWS', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test'],
                      );

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

    /** @test */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'],
                [RegisteredClaims::AUDIENCE => 'test'],
            );

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

    /** @test */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT'],
                [RegisteredClaims::AUDIENCE => 'test'],
            );

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

    /** @test */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test'],
            );

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

    /** @test */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                [RegisteredClaims::AUDIENCE => 'test'],
            );

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

    /** @test */
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => 1486930757.023055,
        ];

        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data,
            );

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

    /** @test */
    public function parseMustConvertStringDates(): void
    {
        $data = [RegisteredClaims::NOT_BEFORE => '1486930757.000000'];

        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data,
            );

        $token = $this->createParser()->parse('a.b.c');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.000000'),
            $claims->get(RegisteredClaims::NOT_BEFORE),
        );
    }

    /** @test */
    public function parseShouldRaiseExceptionOnInvalidDate(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => '14/10/2018 10:50:10.10 UTC'];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data,
            );

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('Value is not in the allowed date format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parse('a.b.c');
    }

    /** @test */
    public function parseShouldRaiseExceptionOnTimestampBeyondDateTimeImmutableRange(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => -10000000000 ** 5];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data,
            );

        $this->expectException(InvalidTokenStructure::class);
        $this->createParser()->parse('a.b.c');
    }
}
