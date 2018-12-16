<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Jose\Parsing\Decoder;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ParserTest extends TestCase
{
    /**
     * @var Decoder|MockObject
     */
    protected $decoder;

    /**
     * @before
     */
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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parse('');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidHeaders(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Headers must be an array');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     */
    public function parseMustRaiseExceptionWhenTypeHeaderIsNotConfigured(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['alg' => 'none']);

        $parser = $this->createParser();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('The header "typ" must be present');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidClaims(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Claims must be an array');

        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed(): void
    {
        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $this->decoder->expects(self::at(4))
                      ->method('base64UrlDecode')
                      ->with('c')
                      ->willReturn('c_dec');

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
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     * @covers \Lcobucci\JWT\Token\Parser::convertDate
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::NOT_BEFORE => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => '1486930757.023055',
        ];

        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn($data);

        $token = $this->createParser()->parse('a.b.');
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U', '1486930663'),
            $claims->get(RegisteredClaims::ISSUED_AT)
        );

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U', '1486930663'),
            $claims->get(RegisteredClaims::NOT_BEFORE)
        );

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.023055'),
            $claims->get(RegisteredClaims::EXPIRATION_TIME)
        );
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     * @covers \Lcobucci\JWT\Token\Parser::convertDate
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseShouldRaiseExceptionOnInvalidDate(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => '14/10/2018 10:50:10.10 UTC'];

        $this->decoder->expects(self::at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects(self::at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects(self::at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects(self::at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn($data);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Given value is not in the allowed format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parse('a.b.');
    }
}
