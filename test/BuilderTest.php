<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Claim\Factory as ClaimFactory;
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
        $this->claimFactory = $this->getMock(ClaimFactory::class, [], [], '', false);
        $this->defaultClaim = $this->getMock(Claim::class);

        $this->claimFactory->expects($this->any())
                           ->method('create')
                           ->willReturn($this->defaultClaim);
    }

    /**
     * @return Builder
     */
    private function createBuilder()
    {
        return new Builder($this->encoder, $this->claimFactory);
    }

    /**
     * @test
     * @covers ::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = $this->createBuilder();

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals([], 'claims', $builder);
        $this->assertAttributeEquals(null, 'signature', $builder);
        $this->assertAttributeSame($this->encoder, 'encoder', $builder);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $builder);
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
        $builder = $this->createBuilder();
        $builder->setAudience('test');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setAudience('test', true);

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'aud' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setExpiration('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setExpiration('2', true);

        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'exp' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setId('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setId('2', true);

        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'jti' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setIssueAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setIssueAt('2', true);

        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iat' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setIssuer('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setIssuer('2', true);

        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iss' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setNotBefore('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setNotBefore('2', true);

        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'nbf' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
        $builder->setSubject('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'header', $builder);
        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);
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
        $builder = $this->createBuilder();
        $builder->setSubject('2', true);

        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'sub' => $this->defaultClaim],
            'header',
            $builder
        );
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
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->setSubject('2'));
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     */
    public function setMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->set('userId', 2);

        $this->assertAttributeEquals(['userId' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     * @covers ::__construct
     * @covers ::set
     */
    public function setMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

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
        $builder = $this->createBuilder();
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
        $signer = $this->getMock(Signer::class);
        $signature = $this->getMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();
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
        $signer = $this->getMock(Signer::class);
        $signature = $this->getMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();

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
        $signer = $this->getMock(Signer::class);
        $signature = $this->getMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');
        $builder->set('test', 123);
    }
}
