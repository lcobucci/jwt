<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class BuilderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $encoder;

    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $signer;

    /**
     * @before
     */
    public function initializeDependencies()
    {
        $this->encoder = $this->createMock(Encoder::class);
        $this->signer = $this->createMock(Signer::class);
    }

    /**
     * @return Builder
     */
    private function createBuilder(): Builder
    {
        return new Builder($this->encoder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Builder::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = $this->createBuilder();

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([], 'claims', $builder);
        self::assertAttributeEquals(null, 'signature', $builder);
        self::assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByMustAppendToTheAudClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedBy('test');
        $builder->canOnlyBeUsedBy('test2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['aud' => ['test', 'test2']], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setAudienceCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedBy('test', true);

        self::assertAttributeEquals(['aud' => ['test']], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'aud' => ['test']],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setAudienceMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedBy('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::expiresAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustChangeTheExpClaim()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt(2);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['exp' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::expiresAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt(2, true);

        self::assertAttributeEquals(['exp' => 2], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'exp' => 2],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::expiresAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->expiresAt(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIdMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['jti' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIdCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2', true);

        self::assertAttributeEquals(['jti' => '2'], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'jti' => '2'],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIdMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuedAtMustChangeTheIatClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt(2);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['iat' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuedAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt(2, true);

        self::assertAttributeEquals(['iat' => 2], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iat' => 2],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedAt
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuedAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedAt(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuerMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['iss' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuerCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2', true);

        self::assertAttributeEquals(['iss' => '2'], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'iss' => '2'],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::issuedBy
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setIssuerMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setNotBeforeMustChangeTheNbfClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter(2);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['nbf' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setNotBeforeCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter(2, true);

        self::assertAttributeEquals(['nbf' => 2], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'nbf' => 2],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setNotBeforeMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedAfter(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::relatedTo
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setSubjectMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['sub' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::relatedTo
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setSubjectCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2', true);

        self::assertAttributeEquals(['sub' => '2'], 'claims', $builder);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'sub' => '2'],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     *
     * @covers \Lcobucci\JWT\Builder::relatedTo
     * @covers \Lcobucci\JWT\Builder::setRegisteredClaim
     */
    public function setSubjectMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Builder::with
     */
    public function setMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->with('userId', 2);

        self::assertAttributeEquals(['userId' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Builder::with
     */
    public function setMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->with('userId', 2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Builder::withHeader
     */
    public function setHeaderMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withHeader('userId', 2);

        self::assertAttributeEquals(
            ['alg' => 'none', 'typ' => 'JWT', 'userId' => 2],
            'headers',
            $builder
        );
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Builder::withHeader
     */
    public function setHeaderMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::getToken
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token
     *
     * @covers \Lcobucci\JWT\Builder::sign
     */
    public function signMustChangeTheSignature()
    {
        $this->signer->method('sign')->willReturn('testing');

        $builder = $this->createBuilder();
        $builder->sign($this->signer, new Key('test'));

        self::assertAttributeEquals('testing', 'signature', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::getToken
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token
     *
     * @covers \Lcobucci\JWT\Builder::sign
     */
    public function signMustKeepAFluentInterface(): Builder
    {
        $this->signer->method('sign')->willReturn('testing');

        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->sign($this->signer, new Key('test')));

        return $builder;
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers \Lcobucci\JWT\Builder::unsign
     */
    public function unsignMustRemoveTheSignature(Builder $builder)
    {
        $builder->unsign();

        self::assertAttributeSame(null, 'signature', $builder);
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers \Lcobucci\JWT\Builder::unsign
     */
    public function unsignMustKeepAFluentInterface(Builder $builder)
    {
        self::assertSame($builder, $builder->unsign());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::sign
     * @uses \Lcobucci\JWT\Builder::getToken
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token
     *
     * @covers \Lcobucci\JWT\Builder::with
     *
     * @expectedException \BadMethodCallException
     */
    public function setMustRaiseExceptionWhenTokenHasBeenSigned()
    {
        $this->signer->method('sign')->willReturn('testing');

        $builder = $this->createBuilder();
        $builder->sign($this->signer, new Key('test'));
        $builder->with('test', 123);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::sign
     * @uses \Lcobucci\JWT\Builder::getToken
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token
     *
     * @covers \Lcobucci\JWT\Builder::withHeader
     *
     * @expectedException \BadMethodCallException
     */
    public function setHeaderMustRaiseExceptionWhenTokenHasBeenSigned()
    {
        $this->signer->method('sign')->willReturn('testing');

        $builder = $this->createBuilder();
        $builder->sign($this->signer, new Key('test'));
        $builder->withHeader('test', 123);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::with
     * @uses \Lcobucci\JWT\Builder::sign
     * @uses \Lcobucci\JWT\Token
     * @uses \Lcobucci\JWT\Signature
     *
     * @covers \Lcobucci\JWT\Builder::getToken
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $this->signer->method('sign')->willReturn('testing');

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => 123]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['testing'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->with('test', 123);

        $builderSign = new \ReflectionProperty($builder, 'signature');
        $builderSign->setAccessible(true);
        $builderSign->setValue($builder, 'testing');

        $token = $builder->getToken();

        self::assertAttributeEquals(['1', '2', '3'], 'payload', $token);
        self::assertAttributeEquals($token->getHeaders(), 'headers', $builder);
        self::assertAttributeEquals($token->getClaims(), 'claims', $builder);
        self::assertAttributeNotEmpty('signature', $builder);
    }
}
