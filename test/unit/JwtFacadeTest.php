<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\TimeRequired;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Lcobucci\JWT\JwtFacade
 *
 * @uses  \Lcobucci\JWT\Token\Parser
 * @uses  \Lcobucci\JWT\Encoding\JoseEncoder
 * @uses  \Lcobucci\JWT\Encoding\ChainedFormatter
 * @uses  \Lcobucci\JWT\Encoding\UnifyAudience
 * @uses  \Lcobucci\JWT\Encoding\UnixTimestampDates
 * @uses  \Lcobucci\JWT\Signer\Hmac
 * @uses  \Lcobucci\JWT\Signer\Hmac\Sha256
 * @uses  \Lcobucci\JWT\Signer\Hmac\Sha384
 * @uses  \Lcobucci\JWT\Signer\Key\InMemory
 * @uses  \Lcobucci\JWT\SodiumBase64Polyfill
 * @uses  \Lcobucci\JWT\Token\Builder
 * @uses  \Lcobucci\JWT\Token\DataSet
 * @uses  \Lcobucci\JWT\Token\Plain
 * @uses  \Lcobucci\JWT\Token\Signature
 * @uses  \Lcobucci\JWT\Validation\Validator
 * @uses  \Lcobucci\JWT\Validation\Constraint\IssuedBy
 * @uses  \Lcobucci\JWT\Validation\Constraint\SignedWith
 * @uses  \Lcobucci\JWT\Validation\Constraint\StrictValidAt
 * @uses  \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @uses  \Lcobucci\JWT\Token\TimedRequiringBuilder
 */
final class JwtFacadeTest extends TestCase
{
    private FrozenClock $clock;
    private Sha256 $signer;
    private InMemory $key;
    private string $issuer;

    protected function setUp(): void
    {
        $this->clock  = new FrozenClock(new DateTimeImmutable('2021-07-10'));
        $this->signer = new Sha256();
        $this->key    = InMemory::plainText('foo');
        $this->issuer = 'bar';
    }

    private function createToken(): string
    {
        return (new JwtFacade())->getBuilder()
            ->issuedAt($this->clock->now())
            ->canOnlyBeUsedAfter($this->clock->now())
            ->expiresAt($this->clock->now()->add(new DateInterval('PT5M')))
            ->issuedBy($this->issuer)
            ->getToken($this->signer, $this->key)
            ->toString();
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     *
     * @uses \Lcobucci\JWT\Token\TimeRequired
     */
    public function requireToIssueTimedTokensOnly(): void
    {
        $this->expectException(TimeRequired::class);

        (new JwtFacade())->getBuilder()->getToken($this->signer, $this->key);
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     * @covers ::parse
     */
    public function goodJwt(): void
    {
        $token = (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer)
        );

        self::assertInstanceOf(Plain::class, $token);
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     * @covers ::parse
     */
    public function badSigner(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signer mismatch');

        (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith(new Sha384(), $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer)
        );
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     * @covers ::parse
     */
    public function badKey(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signature mismatch');

        (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith($this->signer, InMemory::plainText('xyz')),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer)
        );
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     * @covers ::parse
     */
    public function badTime(): void
    {
        $token = $this->createToken();
        $this->clock->setTo($this->clock->now()->add(new DateInterval('P30D')));

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token is expired');

        (new JwtFacade())->parse(
            $token,
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer)
        );
    }

    /**
     * @test
     *
     * @covers ::getBuilder
     * @covers ::parse
     */
    public function badIssuer(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy('xyz')
        );
    }
}
