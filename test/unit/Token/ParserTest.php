<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\Jose\Parsing\Decoder;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class ParserTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoder;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->decoder = $this->createMock(Decoder::class);
    }

    /**
     * @return Parser
     */
    private function createParser(): Parser
    {
        return new Parser($this->decoder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Parser::__construct
     */
    public function constructMustConfigureTheAttributes(): void
    {
        $parser = $this->createParser();

        self::assertAttributeSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();
        $parser->parse('');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     *
     * @expectedException \RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded(): void
    {
        $this->decoder->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('b');

        $this->decoder->method('jsonDecode')
                      ->with('b')
                      ->willThrowException(new RuntimeException());

        $parser = $this->createParser();
        $parser->parse('a.b.');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();
        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(Signature::fromEmptyData(), 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(Signature::fromEmptyData(), 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(Signature::fromEmptyData(), 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals(Signature::fromEmptyData(), 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed(): void
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn([RegisteredClaims::AUDIENCE => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->with('c')
                      ->willReturn('c_dec');

        $parser = $this->createParser();
        $token  = $parser->parse('a.b.c');

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals($signature, 'signature', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Parser::__construct
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Parser::parse
     * @covers \Lcobucci\JWT\Token\Parser::splitJwt
     * @covers \Lcobucci\JWT\Token\Parser::parseHeader
     * @covers \Lcobucci\JWT\Token\Parser::parseClaims
     * @covers \Lcobucci\JWT\Token\Parser::parseSignature
     * @covers \Lcobucci\JWT\Token\Parser::convertDate
     */
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::NOT_BEFORE => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => '1486930757.023055'
        ];

        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn($data);

        /** @var Plain $token */
        $token  = $this->createParser()->parse('a.b.');
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
}
