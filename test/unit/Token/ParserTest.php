<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\Jose\Parsing\Decoder;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
final class ParserTest extends \PHPUnit_Framework_TestCase
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
        $token = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new DataSet([RegisteredClaims::AUDIENCE => 'test'], 'b');

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
        $token = $parser->parse('a.b.');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims = new DataSet([RegisteredClaims::AUDIENCE => 'test'], 'b');

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
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT'], 'a');
        $claims = new DataSet([RegisteredClaims::AUDIENCE => 'test'], 'b');

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
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims = new DataSet([RegisteredClaims::AUDIENCE => 'test'], 'b');

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
        $token = $parser->parse('a.b.c');

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims = new DataSet([RegisteredClaims::AUDIENCE => 'test'], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertAttributeEquals($headers, 'headers', $token);
        self::assertAttributeEquals($claims, 'claims', $token);
        self::assertAttributeEquals($signature, 'signature', $token);
    }
}
