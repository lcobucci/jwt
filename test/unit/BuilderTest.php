<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Claim\EqualsTo;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Claim\GreaterOrEqualsTo;
use Lcobucci\JWT\Claim\LesserOrEqualsTo;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token\RegisteredClaimGiven;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass \Lcobucci\JWT\Builder
 *
 * @covers \Lcobucci\JWT\Token\DataSet
 *
 * @uses \Lcobucci\JWT\Claim\Factory
 * @uses \Lcobucci\JWT\Claim\EqualsTo
 * @uses \Lcobucci\JWT\Claim\Basic
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signer\Key
 */
class BuilderTest extends \PHPUnit\Framework\TestCase
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
        $this->encoder = $this->createMock(Encoder::class);
    }

    /**
     * @return Builder
     */
    private function createBuilder()
    {
        return new Builder($this->encoder, new ClaimFactory());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::permittedFor
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function permittedForMustChangeTheAudClaim()
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['aud' => new EqualsTo('aud', 'test')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::permittedFor
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function permittedForCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'aud' => new EqualsTo('aud', 'test')], $token->getHeaders());
        self::assertEquals(['aud' => new EqualsTo('aud', 'test')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::permittedFor
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function permittedForMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->permittedFor('test'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::expiresAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function expiresAtMustChangeTheExpClaim()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['exp' => new GreaterOrEqualsTo('exp', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::expiresAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function expiresAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->expiresAt('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'exp' => new GreaterOrEqualsTo('exp', 2)], $token->getHeaders());
        self::assertEquals(['exp' => new GreaterOrEqualsTo('exp', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::expiresAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->expiresAt('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::identifiedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function identifiedByMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['jti' => new EqualsTo('jti', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::identifiedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function identifiedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'jti' => new EqualsTo('jti', 2)], $token->getHeaders());
        self::assertEquals(['jti' => new EqualsTo('jti', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::identifiedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function identifiedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedAtMustChangeTheIatClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['iat' => new LesserOrEqualsTo('iat', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedAtCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'iat' => new LesserOrEqualsTo('iat', 2)], $token->getHeaders());
        self::assertEquals(['iat' => new LesserOrEqualsTo('iat', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedAt
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function issuedAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedAt('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedByMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['iss' => new EqualsTo('iss', '2')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedByCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'iss' => new EqualsTo('iss', '2')], $token->getHeaders());
        self::assertEquals(['iss' => new EqualsTo('iss', '2')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::issuedBy
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function issuedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::canOnlyBeUsedAfter
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['nbf' => new LesserOrEqualsTo('nbf', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::canOnlyBeUsedAfter
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function canOnlyBeUsedAfterCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'nbf' => new LesserOrEqualsTo('nbf', 2)], $token->getHeaders());
        self::assertEquals(['nbf' => new LesserOrEqualsTo('nbf', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::canOnlyBeUsedAfter
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedAfter('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::relatedTo
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function relatedToMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['sub' => new EqualsTo('sub', '2')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::relatedTo
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function relatedToCanReplicateItemOnHeader()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2', true);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'sub' => new EqualsTo('sub', '2')], $token->getHeaders());
        self::assertEquals(['sub' => new EqualsTo('sub', '2')], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::relatedTo
     * @covers ::setRegisteredClaim
     * @covers ::configureClaim
     */
    public function relatedToMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withClaim
     * @covers ::configureClaim
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function withClaimMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withClaim('userId', 2);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['userId' => new Basic('userId', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withClaim
     * @covers ::configureClaim
     */
    public function withClaimMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withClaim('userId', 2));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withClaim
     * @covers \Lcobucci\JWT\Token\RegisteredClaimGiven
     */
    public function withClaimShouldThrowExceptionWhenTryingToConfigureARegisteredClaim()
    {
        $this->expectException(RegisteredClaimGiven::class);

        $this->createBuilder()->withClaim('sub', 'me');
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withHeader
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function withHeaderMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withHeader('userId', 2);

        $token = $builder->getToken();

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none', 'userId' => 2], $token->getHeaders());
        self::assertEquals([], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withHeader
     */
    public function withHeaderMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::sign
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function signMustConfigureSignerAndKey()
    {
        $signer = $this->createMock(Signer::class);

        $builder = $this->createBuilder();
        $builder->sign($signer, 'test');

        self::assertAttributeSame($signer, 'signer', $builder);
        self::assertAttributeEquals(new Key('test'), 'key', $builder);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::sign
     */
    public function signMustKeepAFluentInterface()
    {
        $signer = $this->createMock(Signer::class);
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->sign($signer, 'test'));

        return $builder;
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers ::unsign
     */
    public function unsignMustRemoveTheSignerAndKey(Builder $builder)
    {
        $builder->unsign();

        self::assertAttributeSame(null, 'signer', $builder);
        self::assertAttributeSame(null, 'key', $builder);
    }

    /**
     * @test
     *
     * @depends signMustKeepAFluentInterface
     *
     * @covers ::unsign
     */
    public function unsignMustKeepAFluentInterface(Builder $builder)
    {
        self::assertSame($builder, $builder->unsign());
    }

    /**
     * @test
     *
     * @covers ::getToken
     * @covers ::createSignature
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::configureClaim
     * @uses \Lcobucci\JWT\Builder::withClaim
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $signer = $this->createMock(Signer::class);
        $signature = $this->createMock(Signature::class);

        $signer->method('sign')->willReturn($signature);

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => new Basic('test', 123)]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], [$signature])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->withClaim('test', 123);
        $token = $builder->getToken($signer, new Key('testing'));

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['test' => new Basic('test', 123)], $token->getClaims());
        self::assertSame($signature, $token->signature());
        self::assertSame('1.2.3', $token->toString());
    }
}
