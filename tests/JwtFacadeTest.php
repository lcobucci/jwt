<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use AssertionError;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;

/**
 * @covers ::__construct
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
 * @uses  \Lcobucci\JWT\Validation\ConstraintViolation
 * @uses  \Lcobucci\JWT\Validation\RequiredConstraintsViolated
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
        $this->key    = InMemory::base64Encoded('qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=');
        $this->issuer = 'bar';
    }

    private function createToken(): string
    {
        return (new JwtFacade(clock: $this->clock))->issue(
            $this->signer,
            $this->key,
            function (Builder $builder, DateTimeImmutable $issuedAt): Builder {
                return $builder
                    ->expiresAt($issuedAt->modify('+5 minutes'))
                    ->issuedBy($this->issuer);
            },
        )->toString();
    }

    /**
     * @test
     *
     * @covers ::issue
     * @covers ::parse
     */
    public function issueSetTimeValidity(): void
    {
        $token = (new JwtFacade(clock: $this->clock))->issue(
            $this->signer,
            $this->key,
            static fn (Builder $builder): Builder => $builder,
        );

        $now = $this->clock->now();

        self::assertTrue($token->hasBeenIssuedBefore($now));
        self::assertTrue($token->isMinimumTimeBefore($now));
        self::assertFalse($token->isExpired($now));

        $aYearAgo = $now->modify('-1 year');

        self::assertFalse($token->hasBeenIssuedBefore($aYearAgo));
        self::assertFalse($token->isMinimumTimeBefore($aYearAgo));
        self::assertFalse($token->isExpired($aYearAgo));

        $inOneYear = $now->modify('+1 year');

        self::assertTrue($token->hasBeenIssuedBefore($inOneYear));
        self::assertTrue($token->isMinimumTimeBefore($inOneYear));
        self::assertTrue($token->isExpired($inOneYear));
    }

    /**
     * @test
     *
     * @covers ::issue
     * @covers ::parse
     */
    public function issueAllowsTimeValidityOverwrite(): void
    {
        $then  = new DateTimeImmutable('2001-02-03 04:05:06');
        $token = (new JwtFacade())->issue(
            $this->signer,
            $this->key,
            static function (Builder $builder) use ($then): Builder {
                return $builder
                    ->issuedAt($then)
                    ->canOnlyBeUsedAfter($then)
                    ->expiresAt($then->modify('+1 minute'));
            },
        );

        $now = $then->modify('+30 seconds');

        self::assertTrue($token->hasBeenIssuedBefore($now));
        self::assertTrue($token->isMinimumTimeBefore($now));
        self::assertFalse($token->isExpired($now));

        $aYearAgo = $then->modify('-1 year');

        self::assertFalse($token->hasBeenIssuedBefore($aYearAgo));
        self::assertFalse($token->isMinimumTimeBefore($aYearAgo));
        self::assertFalse($token->isExpired($aYearAgo));

        $inOneYear = $then->modify('+1 year');

        self::assertTrue($token->hasBeenIssuedBefore($inOneYear));
        self::assertTrue($token->isMinimumTimeBefore($inOneYear));
        self::assertTrue($token->isExpired($inOneYear));
    }

    /**
     * @test
     *
     * @covers ::issue
     * @covers ::parse
     */
    public function goodJwt(): void
    {
        $token = (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer),
        );

        self::assertInstanceOf(Plain::class, $token);
    }

    /**
     * @test
     *
     * @covers ::issue
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
            new IssuedBy($this->issuer),
        );
    }

    /**
     * @test
     *
     * @covers ::issue
     * @covers ::parse
     */
    public function badKey(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signature mismatch');

        (new JwtFacade())->parse(
            $this->createToken(),
            new SignedWith($this->signer, InMemory::base64Encoded('czyPTpN595zVNSuvoNNlXCRFgXS2fHscMR36dGojaUE=')),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer),
        );
    }

    /**
     * @test
     *
     * @covers ::issue
     * @covers ::parse
     */
    public function badTime(): void
    {
        $token = $this->createToken();
        $this->clock->setTo($this->clock->now()->modify('+30 days'));

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token is expired');

        (new JwtFacade())->parse(
            $token,
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer),
        );
    }

    /**
     * @test
     *
     * @covers ::issue
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
            new IssuedBy('xyz'),
        );
    }

    /**
     * @test
     *
     * @covers ::parse
     */
    public function parserForNonUnencryptedTokens(): void
    {
        $this->expectException(AssertionError::class);

        (new JwtFacade(new UnsupportedParser()))->parse(
            'a.very-broken.token',
            new SignedWith($this->signer, $this->key),
            new StrictValidAt($this->clock),
            new IssuedBy($this->issuer),
        );
    }
}
