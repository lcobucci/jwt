<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing\Decoder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class ParserTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoder;

    /**
     * @var ClaimFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $claimFactory;

    /**
     * @var Claim|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $defaultClaim;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->decoder = $this->createMock(Decoder::class);
        $this->claimFactory = $this->createMock(ClaimFactory::class);
        $this->defaultClaim = $this->createMock(Claim::class);

        $this->claimFactory->method('create')
                           ->willReturn($this->defaultClaim);
    }

    /**
     * @return Parser
     */
    private function createParser(): Parser
    {
        return new Parser($this->decoder, $this->claimFactory);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Parser::__construct
     */
    public function constructMustConfigureTheAttributes()
    {
        $parser = $this->createParser();

        $this->assertAttributeSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $parser);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSDoNotHaveThreeParts()
    {
        $parser = $this->createParser();
        $parser->parse('');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     *
     * @expectedException \RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded()
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
     * @uses \Lcobucci\JWT\Parser::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     *
     * @expectedException \InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken()
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();
        $parser->parse('a.a.');
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     * @covers \Lcobucci\JWT\Parser::parseClaims
     * @covers \Lcobucci\JWT\Parser::parseSignature
     *
     */
    public function parseMustReturnANonSignedTokenWhenSignatureIsNotInformed()
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
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'none'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['a', 'b'], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     * @covers \Lcobucci\JWT\Parser::parseClaims
     * @covers \Lcobucci\JWT\Parser::parseSignature
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded()
    {
        $this->decoder->expects($this->at(0))
                      ->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('a_dec');

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->with('a_dec')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', 'aud' => 'test']);

        $this->decoder->expects($this->at(2))
                      ->method('base64UrlDecode')
                      ->with('b')
                      ->willReturn('b_dec');

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->with('b_dec')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.');

        $this->assertAttributeEquals(
            ['typ' => 'JWT', 'alg' => 'none', 'aud' => $this->defaultClaim],
            'headers',
            $token
        );

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['a', 'b'], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     * @covers \Lcobucci\JWT\Parser::parseClaims
     * @covers \Lcobucci\JWT\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing()
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
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertAttributeEquals(['typ' => 'JWT'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['a', 'b'], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     * @uses \Lcobucci\JWT\Token::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     * @covers \Lcobucci\JWT\Parser::parseClaims
     * @covers \Lcobucci\JWT\Parser::parseSignature
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone()
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
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'none'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeEquals(['a', 'b'], 'payload', $token);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Parser::__construct
     * @uses \Lcobucci\JWT\Token::__construct
     * @uses \Lcobucci\JWT\Signature::__construct
     *
     * @covers \Lcobucci\JWT\Parser::parse
     * @covers \Lcobucci\JWT\Parser::splitJwt
     * @covers \Lcobucci\JWT\Parser::parseHeader
     * @covers \Lcobucci\JWT\Parser::parseClaims
     * @covers \Lcobucci\JWT\Parser::parseSignature
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed()
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
                      ->willReturn(['aud' => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->with('c')
                      ->willReturn('c_dec');

        $parser = $this->createParser();
        $token = $parser->parse('a.b.c');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'HS256'], 'headers', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(new Signature('c_dec'), 'signature', $token);
        $this->assertAttributeEquals(['a', 'b', 'c'], 'payload', $token);
    }
}
