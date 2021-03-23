<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Decoder;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/** @coversDefaultClass \Lcobucci\JWT\Token\Parser */
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

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parse('');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     */
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

        $parser->parse('a.b.');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidHeaders(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers \Lcobucci\JWT\Token\UnsupportedHeaderFound
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(UnsupportedHeaderFound::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidClaims(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWT', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConfigureTypeToJWTWhenItIsMissing(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustNotChangeTypeWhenItIsConfigured(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWS', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWS', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
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
                [RegisteredClaims::AUDIENCE => 'test']
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

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers ::convertDate
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => 1486930757.023055,
        ];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data
            );

        $token = $this->createParser()->parse('a.b.');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U', '1486930663'),
            $claims->get(RegisteredClaims::ISSUED_AT)
        );

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.023055'),
            $claims->get(RegisteredClaims::EXPIRATION_TIME)
        );
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers ::convertDate
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConvertStringDates(): void
    {
        $data = [RegisteredClaims::NOT_BEFORE => '1486930757.000000'];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data
            );

        $token = $this->createParser()->parse('a.b.');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.000000'),
            $claims->get(RegisteredClaims::NOT_BEFORE)
        );
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers ::convertDate
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
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
                $data
            );

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('Value is not in the allowed date format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parse('a.b.');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers ::convertDate
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
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
                $data
            );

        $this->expectException(InvalidTokenStructure::class);
        $this->createParser()->parse('a.b.');
    }
}
