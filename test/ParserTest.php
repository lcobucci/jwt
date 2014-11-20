<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Factory;
use RuntimeException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass Lcobucci\JWT\Parser
 */
class ParserTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $encoder;

    /**
     * @var Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $decoder;

    /**
     * @var Factory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $factory;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->encoder = $this->getMockBuilder(Encoder::class)
                              ->setMockClassName('EncoderMock')
                              ->getMock();

        $this->decoder = $this->getMockBuilder(Decoder::class)
                              ->setMockClassName('DecoderMock')
                              ->getMock();

        $this->factory = $this->getMockBuilder(Factory::class)
                              ->setMockClassName('FactoryMock')
                              ->getMock();
    }

    /**
     * @test
     * @covers ::__construct
     */
    public function constructMustConfigureTheAttributes()
    {
        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $this->assertAttributeSame($this->encoder, 'encoder', $parser);
        $this->assertAttributeSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeSame($this->factory, 'factory', $parser);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSIsNotAString()
    {
        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse(['asdasd']);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenJWSDontHaveThreeParts()
    {
        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse('');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     *
     * @expectedException RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willThrowException(new RuntimeException());

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse('asdfad.asdfasdf.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsNotAnArray()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willReturn('asdfasdfasd');

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse('a.a.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse('a.a.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenClaimSetIsNotAnArray()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn('asdfasdfasd');

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $parser->parse('a.a.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     */
    public function parseMustReturnANonSignedTokenWhenSignatureIsNotInformed()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $token = $parser->parse('a.a.');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'none'], 'header', $token);
        $this->assertAttributeEquals(['aud' => 'test'], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeSame($this->encoder, 'encoder', $token);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Signature::__construct
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed()
    {
        $signer = $this->getMockBuilder(Signer::class)
                       ->setMockClassName('SignerMock')
                       ->getMock();

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->willReturn('aaa');

        $this->factory->expects($this->any())
                      ->method('create')
                      ->willReturn($signer);

        $parser = new Parser($this->encoder, $this->decoder, $this->factory);

        $token = $parser->parse('a.a.a');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'HS256'], 'header', $token);
        $this->assertAttributeEquals(['aud' => 'test'], 'claims', $token);
        $this->assertAttributeEquals(new Signature($signer, 'aaa'), 'signature', $token);
        $this->assertAttributeSame($this->encoder, 'encoder', $token);
    }
}
