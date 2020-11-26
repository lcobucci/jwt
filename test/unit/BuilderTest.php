<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use DateTimeImmutable;
use Lcobucci\JWT\Claim\Basic;
use Lcobucci\JWT\Claim\EqualsTo;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Claim\GreaterOrEqualsTo;
use Lcobucci\JWT\Claim\LesserOrEqualsTo;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Token\RegisteredClaimGiven;
use PHPUnit\Framework\TestCase;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 *
 * @coversDefaultClass \Lcobucci\JWT\Builder
 *
 * @covers \Lcobucci\JWT\Token\DataSet
 * @covers \Lcobucci\JWT\Signature
 *
 * @uses \Lcobucci\JWT\Claim\Factory
 * @uses \Lcobucci\JWT\Claim\EqualsTo
 * @uses \Lcobucci\JWT\Claim\Basic
 * @uses \Lcobucci\JWT\Token
 * @uses \Lcobucci\JWT\Signer\BaseSigner
 * @uses \Lcobucci\JWT\Signer\Key
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 * @uses \Lcobucci\JWT\Signer\None
 */
class BuilderTest extends TestCase
{
    use CheckForDeprecations;

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function permittedForMustChangeTheAudClaim()
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function permittedForCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->permittedFor('test', true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function expiresAtMustChangeTheExpClaim()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

        $builder = $this->createBuilder();
        $builder->expiresAt('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function expiresAtCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->expiresAt(new DateTimeImmutable('@2'), true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     */
    public function expiresAtMustKeepAFluentInterface()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function identifiedByMustChangeTheJtiClaim()
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function identifiedByCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->identifiedBy('2', true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedAtMustChangeTheIatClaim()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

        $builder = $this->createBuilder();
        $builder->issuedAt('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedAtCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->issuedAt(new DateTimeImmutable('@2'), true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     */
    public function issuedAtMustKeepAFluentInterface()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedByMustChangeTheIssClaim()
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function issuedByCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->issuedBy('2', true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function canOnlyBeUsedAfterCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter(new DateTimeImmutable('@2'), true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertToDate
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface()
    {
        $this->expectDeprecation('Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.');

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function relatedToMustChangeTheSubClaim()
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function relatedToCanReplicateItemOnHeader()
    {
        $this->expectDeprecation('Replicating claims as headers is deprecated and will removed from v4.0. Please manually set the header if you need it replicated.');

        $builder = $this->createBuilder();
        $builder->relatedTo('2', true);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     * @covers ::forwardCallToCorrectClaimMethod
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function withClaimMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withClaim('userId', 2);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['userId' => new Basic('userId', 2)], $token->getClaims());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withClaim
     * @covers ::configureClaim
     * @covers ::forwardCallToCorrectClaimMethod
     */
    public function withClaimMustKeepAFluentInterface()
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withClaim('userId', 2));
    }

    /**
     * @test
     *
     * @param string $name
     * @param mixed $value
     * @param mixed $expected
     * @param null|string $otherMessage
     *
     * @covers ::__construct
     * @covers ::withClaim
     * @covers ::canOnlyBeUsedAfter
     * @covers ::configureClaim
     * @covers ::convertItems
     * @covers ::convertToDate
     * @covers ::getToken
     * @covers ::setRegisteredClaim
     * @covers ::createSignature
     * @covers ::expiresAt
     * @covers ::issuedBy
     * @covers ::identifiedBy
     * @covers ::permittedFor
     * @covers ::forwardCallToCorrectClaimMethod
     * @covers ::issuedAt
     *
     * @dataProvider dataWithClaimDeprecationNotice
     */
    public function withClaimShouldSendDeprecationNoticeWhenTryingToConfigureARegisteredClaim($name, $value, $expected, $otherMessage = null)
    {
        $this->expectDeprecation('The use of the method "withClaim" is deprecated for registered claims. Please use dedicated method instead.');

        if ($otherMessage) {
            $this->expectDeprecation($otherMessage);
        }

        $token = $this->createBuilder()
            ->withClaim($name, $value)
            ->getToken(new None(), Key\InMemory::plainText(''));

        self::assertEquals($expected, $token->claims()->get($name));
    }

    public function dataWithClaimDeprecationNotice()
    {
        $now = time();
        $nowAsDate = new DateTimeImmutable('@' . $now);
        $nowPlus1HourAsDate = $nowAsDate->modify('+1 hour');

        return [
            ['sub', 'me', 'me'],
            ['aud', 'him', ['him']],
            ['jti', '0123456789ABCDEF', '0123456789ABCDEF'],
            ['iss', 'you', 'you'],
            ['exp', $nowPlus1HourAsDate->getTimestamp(), $nowPlus1HourAsDate, 'Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.'],
            ['iat', $now, $nowAsDate, 'Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.'],
            ['nbf', $now, $nowAsDate, 'Using integers for registered date claims is deprecated, please use DateTimeImmutable objects instead.'],
        ];
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::withHeader
     * @covers ::createSignature
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function withHeaderMustConfigureTheGivenClaim()
    {
        $builder = $this->createBuilder();
        $builder->withHeader('userId', 2);

        $token = $builder->getToken(new None(), Key\InMemory::plainText(''));

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::getToken
     */
    public function signMustConfigureSignerAndKey()
    {
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');

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
        $this->expectDeprecation('Implicit conversion of keys from strings is deprecated. Please use InMemory or LocalFileReference classes.');

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
     * @covers ::convertItems
     *
     * @uses \Lcobucci\JWT\Builder::__construct
     * @uses \Lcobucci\JWT\Builder::configureClaim
     * @uses \Lcobucci\JWT\Builder::withClaim
     * @uses \Lcobucci\JWT\Builder::forwardCallToCorrectClaimMethod
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration()
    {
        $signer = $this->createMock(Signer::class);

        $signer->expects(self::once())
            ->method('sign')
            ->willReturn(new Signature('payload-verification-hash'));

        $this->encoder->expects($this->exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([['typ'=> 'JWT', 'alg' => 'none']], [['test' => 123]])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects($this->exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['payload-verification-hash'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = $this->createBuilder()->withClaim('test', 123);
        $token = $builder->getToken($signer, new Key('testing'));

        self::assertEquals(['typ' => 'JWT', 'alg' => 'none'], $token->getHeaders());
        self::assertEquals(['test' => new Basic('test', 123)], $token->getClaims());
        self::assertEquals(new Signature('payload-verification-hash', '3'), $token->signature());
        self::assertSame('1.2.3', $token->toString());
    }
}
