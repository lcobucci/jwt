<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\Jose\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class BuilderTest extends TestCase
{
    /**
     * @var Encoder|MockObject
     */
    protected $encoder;

    /**
     * @var Signer|MockObject
     */
    private $signer;

    /**
     * @before
     */
    public function initializeDependencies(): void
    {
        $this->encoder = $this->createMock(Encoder::class);
        $this->signer  = $this->createMock(Signer::class);
        $this->signer->method('getAlgorithmId')->willReturn('RS256');
    }

    private function createBuilder(): Builder
    {
        return new Builder($this->encoder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     */
    public function constructMustInitializeTheAttributes(): void
    {
        $builder = $this->createBuilder();

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([], 'claims', $builder);
        self::assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function permittedForMustAppendToTheAudClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test');
        $builder->permittedFor('test2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::AUDIENCE => ['test', 'test2']], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function permittedForShouldPreventDuplicatedEntries(): void
    {
        $builder = $this->createBuilder();
        $builder->permittedFor('test');
        $builder->permittedFor('test');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::AUDIENCE => ['test']], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function permittedForMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->permittedFor('test'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function expiresAtMustChangeTheExpClaim(): void
    {
        $now = new DateTimeImmutable();

        $builder = $this->createBuilder();
        $builder->expiresAt($now);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::EXPIRATION_TIME => $now], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function expiresAtMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->expiresAt(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withIdMustChangeTheJtiClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->identifiedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::ID => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withIdMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->identifiedBy('2'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function issuedAtMustChangeTheIatClaim(): void
    {
        $now = new DateTimeImmutable();

        $builder = $this->createBuilder();
        $builder->issuedAt($now);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::ISSUED_AT => $now], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function issuedAtMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedAt(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function issuedByMustChangeTheIssClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->issuedBy('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::ISSUER => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function issuedByMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->issuedBy('2'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function canOnlyBeUsedAfterMustChangeTheNbfClaim(): void
    {
        $now = new DateTimeImmutable();

        $builder = $this->createBuilder();
        $builder->canOnlyBeUsedAfter($now);

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::NOT_BEFORE => $now], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function canOnlyBeUsedAfterMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->canOnlyBeUsedAfter(new DateTimeImmutable()));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function relatedToMustChangeTheSubClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->relatedTo('2');

        self::assertAttributeEquals(['alg' => 'none', 'typ' => 'JWT'], 'headers', $builder);
        self::assertAttributeEquals([RegisteredClaims::SUBJECT => '2'], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function relatedToMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->relatedTo('2'));
    }

    /**
     * @test
     *
     * @expectedException \InvalidArgumentException
     *
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withClaimShouldRaiseExceptionWhenTryingToConfigureARegisteredClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->withClaim(RegisteredClaims::ISSUER, 'me');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withClaimMustConfigureTheGivenClaim(): void
    {
        $builder = $this->createBuilder();
        $builder->withClaim('userId', 2);

        self::assertAttributeEquals(['userId' => 2], 'claims', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withClaimMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withClaim('userId', 2));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withHeaderMustConfigureTheGivenClaim(): void
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
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     */
    public function withHeaderMustKeepAFluentInterface(): void
    {
        $builder = $this->createBuilder();

        self::assertSame($builder, $builder->withHeader('userId', 2));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::getToken
     * @covers \Lcobucci\JWT\Token\Builder::encode
     * @covers \Lcobucci\JWT\Token\Builder::formatClaims
     * @covers \Lcobucci\JWT\Token\Builder::convertDate
     *
     * @uses \Lcobucci\JWT\Token\Builder::__construct
     * @uses \Lcobucci\JWT\Token\Builder::withClaim
     * @uses \Lcobucci\JWT\Token\Builder::setClaim
     * @uses \Lcobucci\JWT\Token\Builder::issuedAt
     * @uses \Lcobucci\JWT\Token\Builder::expiresAt
     * @uses \Lcobucci\JWT\Token\Builder::permittedFor
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function getTokenMustReturnANewTokenWithCurrentConfiguration(): void
    {
        $this->signer->method('sign')->willReturn('testing');

        $issuedAt   = new DateTimeImmutable('@1487285080');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');
        $headers    = ['typ' => 'JWT', 'alg' => 'RS256'];
        $claims     = ['iat' => 1487285080, 'exp' => '1487285080.123456', 'aud' => 'test', 'test' => 123];

        $this->encoder->expects(self::exactly(2))
                      ->method('jsonEncode')
                      ->withConsecutive([self::identicalTo($headers)], [self::identicalTo($claims)])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects(self::exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['testing'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        self::assertInstanceOf(DateTimeImmutable::class, $expiration);

        $token = $this->createBuilder()
                      ->issuedAt($issuedAt)
                      ->expiresAt($expiration)
                      ->permittedFor('test')
                      ->withClaim('test', 123)
                      ->getToken($this->signer, new Key('123'));

        self::assertSame('JWT', $token->headers()->get('typ'));
        self::assertSame('RS256', $token->headers()->get('alg'));
        self::assertSame(123, $token->claims()->get('test'));
        self::assertSame($issuedAt, $token->claims()->get('iat'));
        self::assertSame($expiration, $token->claims()->get('exp'));
        self::assertSame('3', (string) $token->signature());
    }
}
