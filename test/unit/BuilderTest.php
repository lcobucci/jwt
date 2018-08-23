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
 */
class BuilderTest extends \PHPUnit\Framework\TestCase
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
        $this->encoder = $this->createMock(Encoder::class);
        $this->claimFactory = $this->createMock(ClaimFactory::class, [], [], '', false);
        $this->defaultClaim = $this->createMock(Claim::class);

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
     *
     * @covers Lcobucci\JWT\Builder::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = $this->createBuilder();

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals([], 'claims', $builder);
        $this->assertAttributeEquals(null, 'signature', $builder);
        $this->assertAttributeSame($this->encoder, 'encoder', $builder);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByMustChangeTheAudClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedBy('test');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedBy('test', true);

        $this->assertAttributeEquals(['aud' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'aud' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->canOnlyBeUsedBy('test'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::expiresAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustChangeTheExpClaim()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::expiresAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2', true);

        $this->assertAttributeEquals(['exp' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'exp' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::expiresAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->expiresAt('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::identifiedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::identifiedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2', true);

        $this->assertAttributeEquals(['jti' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'jti' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::identifiedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function identifiedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtMustChangeTheIatClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2', true);

        $this->assertAttributeEquals(['iat' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iat' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedAt
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->issuedAt('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedByMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2', true);

        $this->assertAttributeEquals(['iss' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iss' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::issuedBy
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function issuedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2', true);

        $this->assertAttributeEquals(['nbf' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'nbf' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->canOnlyBeUsedAfter('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::relatedTo
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function relatedToMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        $this->assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::relatedTo
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function relatedToCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2', true);

        $this->assertAttributeEquals(['sub' => $this->defaultClaim], 'claims', $builder);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'sub' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     *
     * @covers Lcobucci\JWT\Builder::relatedTo
     * @covers Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function relatedToMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     *
     * @covers Lcobucci\JWT\Builder::with
     */
    public function withMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->with('userId', 2);

        $this->assertAttributeEquals(['userId' => $this->defaultClaim], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     *
     * @covers Lcobucci\JWT\Builder::with
     */
    public function withMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->with('userId', 2));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     *
     * @covers Lcobucci\JWT\Builder::withHeader
     */
    public function withHeaderMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withHeader('userId', 2);

        $this->assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'userId' => $this->defaultClaim],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     *
     * @covers Lcobucci\JWT\Builder::withHeader
     */
    public function withHeaderMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::getToken
     * @uses Lcobucci\JWT\Token
     *
     * @covers Lcobucci\JWT\Builder::sign
     */
    public function signMustChangeTheSignature()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');

        $this->assertAttributeSame($signature, 'signature', $builder);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::getToken
     * @uses Lcobucci\JWT\Token
     *
     * @covers Lcobucci\JWT\Builder::sign
     */
    public function signMustKeepAFluentInterface()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();

        $this->assertSame($builder, $builder->sign($signer, 'test'));

        return $builder;
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers Lcobucci\JWT\Builder::unsign
     */
    public function unsignMustRemoveTheSignature(Builder $builder)
    {
        $builder->unsign();

        $this->assertAttributeSame(null, 'signature', $builder);
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers Lcobucci\JWT\Builder::unsign
     */
    public function unsignMustKeepAFluentInterface(Builder $builder)
    {
        $this->assertSame($builder, $builder->unsign());
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::sign
     * @uses Lcobucci\JWT\Builder::getToken
     * @uses Lcobucci\JWT\Token
     *
     * @covers Lcobucci\JWT\Builder::with
     *
     * @expectedException BadMethodCallException
     */
    public function withMustRaiseExceptionWhenTokenHasBeenSigned()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');
        $builder->with('test', 123);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::sign
     * @uses Lcobucci\JWT\Builder::getToken
     * @uses Lcobucci\JWT\Token
     *
     * @covers Lcobucci\JWT\Builder::withHeader
     *
     * @expectedException BadMethodCallException
     */
    public function withHeaderMustRaiseExceptionWhenTokenHasBeenSigned()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $signer->expects($this->any())
               ->method('sign')
               ->willReturn($signature);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');
        $builder->withHeader('test', 123);
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\Builder::__construct
     * @uses Lcobucci\JWT\Builder::with
     * @uses Lcobucci\JWT\Token
     *
     * @covers Lcobucci\JWT\Builder::getToken
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $signature = $this->createMock(Signature::class, [], [], '', false);

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => $this->defaultClaim]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], [$signature])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->with('test', 123);

        $builderSign = new \ReflectionProperty($builder, 'signature');
        $builderSign->setAccessible(true);
        $builderSign->setValue($builder, $signature);

        $token = $builder->getToken();

        $tokenSign = new \ReflectionProperty($token, 'signature');
        $tokenSign->setAccessible(true);

        $this->assertAttributeEquals(['1', '2', '3'], 'payload', $token);
        $this->assertAttributeEquals($token->getHeaders(), 'headers', $builder);
        $this->assertAttributeEquals($token->getClaims(), 'claims', $builder);
        $this->assertAttributeSame($tokenSign->getValue($token), 'signature', $builder);
    }
}
