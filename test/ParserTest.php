<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Factory as SignerFactory;
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
     * @var SignerFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $signerFactory;

    /**
     * @var ClaimFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $claimFactory;

    /**
     * @var Claim|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $defaultClaim;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->encoder = $this->getMock(Encoder::class);
        $this->decoder = $this->getMock(Decoder::class);
        $this->signerFactory = $this->getMock(SignerFactory::class);
        $this->claimFactory = $this->getMock(ClaimFactory::class, [], [], '', false);
        $this->defaultClaim = $this->getMock(Claim::class);

        $this->claimFactory->expects($this->any())
                           ->method('create')
                           ->willReturn($this->defaultClaim);
    }

    /**
     * @return Parser
     */
    private function createParser()
    {
        return new Parser(
            $this->encoder,
            $this->decoder,
            $this->signerFactory,
            $this->claimFactory
        );
    }

    /**
     * @test
     * @covers ::__construct
     */
    public function constructMustConfigureTheAttributes()
    {
        $parser = $this->createParser();

        $this->assertAttributeSame($this->encoder, 'encoder', $parser);
        $this->assertAttributeSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeSame($this->signerFactory, 'signerFactory', $parser);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $parser);
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
        $parser = $this->createParser();
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
        $parser = $this->createParser();
        $parser->parse('');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::createToken
     * @covers ::parseHeader
     *
     * @expectedException RuntimeException
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willThrowException(new RuntimeException());

        $parser = $this->createParser();
        $parser->parse('asdfad.asdfasdf.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::createToken
     * @covers ::parseHeader
     *
     * @expectedException InvalidArgumentException
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken()
    {
        $this->decoder->expects($this->any())
                      ->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();
        $parser->parse('a.a.');
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::createToken
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

        $parser = $this->createParser();
        $token = $parser->parse('a.a.');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'none'], 'header', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeSame($this->encoder, 'encoder', $token);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::createToken
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded()
    {
        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'none', 'aud' => 'test']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $parser = $this->createParser();
        $token = $parser->parse('a.a.');

        $this->assertAttributeEquals(
            ['typ' => 'JWT', 'alg' => 'none', 'aud' => $this->defaultClaim],
            'header',
            $token
        );

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(null, 'signature', $token);
        $this->assertAttributeSame($this->encoder, 'encoder', $token);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::parse
     * @covers ::splitJwt
     * @covers ::createToken
     * @covers ::parseHeader
     * @covers ::parseClaims
     * @covers ::parseSignature
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Signature::__construct
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed()
    {
        $signer = $this->getMock(Signer::class);

        $this->decoder->expects($this->at(1))
                      ->method('jsonDecode')
                      ->willReturn(['typ' => 'JWT', 'alg' => 'HS256']);

        $this->decoder->expects($this->at(3))
                      ->method('jsonDecode')
                      ->willReturn(['aud' => 'test']);

        $this->decoder->expects($this->at(4))
                      ->method('base64UrlDecode')
                      ->willReturn('aaa');

        $this->signerFactory->expects($this->any())
                      ->method('create')
                      ->willReturn($signer);

        $parser = $this->createParser();
        $token = $parser->parse('a.a.a');

        $this->assertAttributeEquals(['typ' => 'JWT', 'alg' => 'HS256'], 'header', $token);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $token);
        $this->assertAttributeEquals(new Signature($signer, 'aaa'), 'signature', $token);
        $this->assertAttributeSame($this->encoder, 'encoder', $token);
    }
}
