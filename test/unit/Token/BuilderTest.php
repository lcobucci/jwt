<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use Lcobucci\Jose\Parsing\Encoder;
use Lcobucci\JWT\Signer;
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
        $this->signer->method('getAlgorithmId')->willReturn('RS256');
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
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     */
    public function constructMustInitializeTheAttributes()
    {
        $builder = $this->createBuilder();

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([], 'claims', $builder);
        self::assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByShouldPreventDuplicatedEntries()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedBy('test');
        $builder->canOnlyBeUsedBy('test');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['aud' => ['test']], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedBy('test'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->expiresAt(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function withIdMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['jti' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function withIdCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function withIdMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedAtMustChangeTheIatClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedAt(2);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['iat' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedAtCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedAtMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedAt(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedByMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['iss' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedByCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function issuedByMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim()
    {
        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter(2);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['nbf' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedAfter(2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function relatedToMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals(['sub' => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function relatedToCanReplicateItemOnHeader()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     *
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::setRegisteredClaim
     */
    public function relatedToMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Token\Builder::with
     */
    public function withMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->with('userId', 2);

        self::assertAttributeEquals(['userId' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Token\Builder::with
     */
    public function withMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->with('userId', 2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     */
    public function withHeaderMustConfigureTheGivenClaim()
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
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     *
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     */
    public function withHeaderMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Builder::getToken
     * @covers \Lcobucci\JWT\Token\Builder::encode
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $this->signer->method('sign')->willReturn('testing');

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'RS256']], [['test' => 123]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['testing'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->with('test', 123);
        $token = $builder->getToken($this->signer, new Key('123'));

        self::assertSame('JWT', $token->headers()->get('typ'));
        self::assertSame('RS256', $token->headers()->get('alg'));
        self::assertSame(123, $token->claims()->get('test'));
        self::assertNotNull($token->signature());
    }

    /**
     * @test
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::with
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     *
     * @covers \Lcobucci\JWT\Token\Builder::getUnsecuredToken
     * @covers \Lcobucci\JWT\Token\Builder::encode
     */
    public function getUnsecuredTokenShouldReturnATokenWithoutSignature()
    {
        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => 123]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(2))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $builder = $this->createBuilder()->with('test', 123);

        $token = $builder->getUnsecuredToken();

        self::assertSame('JWT', $token->headers()->get('typ'));
        self::assertSame('none', $token->headers()->get('alg'));
        self::assertSame(123, $token->claims()->get('test'));
        self::assertNull($token->signature());
    }
}
