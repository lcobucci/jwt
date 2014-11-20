<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Parsing\Encoder;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass Lcobucci\JWT\Builder
 */
class BuilderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $encoder;

    /**
     * {@inheritdoc}
     */
    protected function setUp()
    {
        $this->encoder = $this->getMockBuilder(Encoder::class)
                              ->setMockClassName('EncoderMock')
                              ->getMock();
    }

    /**
     * @test
     * @covers ::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = new Builder($this->encoder);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals([], 'claims', $builder);
        $this->assertAttributeEquals(null, 'signature', $builder);
        $this->assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setAudience
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setAudienceMustChangeTheAudClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setAudience('test');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['aud' => 'test'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setAudience
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setAudienceCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setAudience('test', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'aud' => 'test'], 'header', $builder);
        $this->assertAttributeEquals(['aud' => 'test'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setAudience
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setAudienceMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setAudience('test'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setExpiration
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setExpirationMustChangeTheExpClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setExpiration('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['exp' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setExpiration
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setExpirationCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setExpiration('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'exp' => 2], 'header', $builder);
        $this->assertAttributeEquals(['exp' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setExpiration
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setExpirationMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setExpiration('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setId
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIdMustChangeTheJtiClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setId('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['jti' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setId
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIdCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setId('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'jti' => '2'], 'header', $builder);
        $this->assertAttributeEquals(['jti' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setId
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIdMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setId('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssueAt
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssueAtMustChangeTheIatClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setIssueAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['iat' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssueAt
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssueAtCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setIssueAt('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'iat' => 2], 'header', $builder);
        $this->assertAttributeEquals(['iat' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssueAt
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssueAtMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setIssueAt('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssuer
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssuerMustChangeTheIssClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setIssuer('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['iss' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssuer
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssuerCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setIssuer('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'iss' => '2'], 'header', $builder);
        $this->assertAttributeEquals(['iss' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setIssuer
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setIssuerMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setIssuer('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setNotBefore
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setNotBeforeMustChangeTheNbfClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setNotBefore('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['nbf' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setNotBefore
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setNotBeforeCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setNotBefore('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'nbf' => 2], 'header', $builder);
        $this->assertAttributeEquals(['nbf' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setNotBefore
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setNotBeforeMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setNotBefore('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setSubject
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setSubjectMustChangeTheSubClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->setSubject('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['sub' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setSubject
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setSubjectCanReplicateItemOnHeader()
    {
        $builder = new Builder($this->encoder);
        $builder->setSubject('2', true);

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT', 'sub' => '2'], 'header', $builder);
        $this->assertAttributeEquals(['sub' => '2'], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::setSubject
     * @covers ::setRegisteredClaim
     * @covers ::set
     */
    public function setSubjectMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->setSubject('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     */
    public function setMustConfigureTheGivenClaim()
    {
        $builder = new Builder($this->encoder);
        $builder->set('userId', 2);

        $this->assertAttributeEquals(['userId' => 2], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     */
    public function setMustKeepAFluentInterface()
    {
        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->set('userId', 2));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     * @covers ::getToken
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Token::getHeader
     * @covers Lcobucci\JWT\Token::getClaims
     * @covers Lcobucci\JWT\Token::getSignature
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $builder = new Builder($this->encoder);
        $token = $builder->set('test', 123)->getToken();

        $this->assertAttributeEquals($token->getHeader(), 'header', $builder);
        $this->assertAttributeEquals($token->getClaims(), 'claims', $builder);
        $this->assertAttributeSame($token->getSignature(), 'signature', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::sign
     * @covers ::getToken
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Token::getPayload
     */
    public function signMustChangeTheSignature()
    {
        $signer = $this->getMockBuilder(Signer::class)
                       ->setMockClassName('SignerMock')
                       ->getMock();

        $signature = $this->getMockBuilder(Signature::class)
                          ->setMockClassName('SignatureMock')
                          ->disableOriginalConstructor()
                          ->getMock();

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = new Builder($this->encoder);
        $builder->sign($signer, 'test');

        $this->assertAttributeSame($signature, 'signature', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::sign
     * @covers ::getToken
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Token::getPayload
     */
    public function signMustKeepAFluentInterface()
    {
        $signer = $this->getMockBuilder(Signer::class)
                       ->setMockClassName('SignerMock')
                       ->getMock();

        $signature = $this->getMockBuilder(Signature::class)
                          ->setMockClassName('SignatureMock')
                          ->disableOriginalConstructor()
                          ->getMock();

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = new Builder($this->encoder);

        $this->assertSame($builder, $builder->sign($signer, 'test'));

        return $builder;
    }

    /**
     * @test
     * @depends signMustKeepAFluentInterface
     * @covers ::unsign
     */
    public function unsignMustRemoveTheSignature(Builder $builder)
    {
        $builder->unsign();

        $this->assertAttributeSame(null, 'signature', $builder);
    }

    /**
     * @test
     * @depends signMustKeepAFluentInterface
     * @covers ::unsign
     */
    public function unsignMustKeepAFluentInterface(Builder $builder)
    {
        $this->assertSame($builder, $builder->unsign());
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     * @covers ::sign
     * @covers ::getToken
     * @covers Lcobucci\JWT\Token::__construct
     * @covers Lcobucci\JWT\Token::setEncoder
     * @covers Lcobucci\JWT\Token::getPayload
     *
     * @expectedException BadMethodCallException
     */
    public function setMustRaiseExceptionWhenTokenHasBeenSigned()
    {
        $signer = $this->getMockBuilder(Signer::class)
                       ->setMockClassName('SignerMock')
                       ->getMock();

        $signature = $this->getMockBuilder(Signature::class)
                          ->setMockClassName('SignatureMock')
                          ->disableOriginalConstructor()
                          ->getMock();

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = new Builder($this->encoder);
        $builder->sign($signer, 'test');
        $builder->set('test', 123);
    }
}
