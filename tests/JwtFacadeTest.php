<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use AssertionError;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Encoding;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;
use Psr\Clock\ClockInterface;

#[PHPUnit\CoversClass(JwtFacade::class)]
#[PHPUnit\UsesClass(Token\Builder::class)]
#[PHPUnit\UsesClass(Token\Parser::class)]
#[PHPUnit\UsesClass(Token\Plain::class)]
#[PHPUnit\UsesClass(Token\DataSet::class)]
#[PHPUnit\UsesClass(Token\Signature::class)]
#[PHPUnit\UsesClass(Encoding\JoseEncoder::class)]
#[PHPUnit\UsesClass(Encoding\ChainedFormatter::class)]
#[PHPUnit\UsesClass(Encoding\UnixTimestampDates::class)]
#[PHPUnit\UsesClass(Encoding\UnifyAudience::class)]
#[PHPUnit\UsesClass(Hmac::class)]
#[PHPUnit\UsesClass(Hmac\Sha256::class)]
#[PHPUnit\UsesClass(Hmac\Sha384::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(Validator::class)]
#[PHPUnit\UsesClass(Constraint\IssuedBy::class)]
#[PHPUnit\UsesClass(Constraint\SignedWith::class)]
#[PHPUnit\UsesClass(Constraint\SignedWithOneInSet::class)]
#[PHPUnit\UsesClass(Constraint\SignedWithUntilDate::class)]
#[PHPUnit\UsesClass(Constraint\StrictValidAt::class)]
#[PHPUnit\UsesClass(ConstraintViolation::class)]
#[PHPUnit\UsesClass(RequiredConstraintsViolated::class)]
final class JwtFacadeTest extends TestCase
{
    private FrozenClock $clock;
    private Hmac\Sha256 $signer;
    private InMemory $key;
    /** @var non-empty-string */
    private string $issuer;

    #[PHPUnit\Before]
    public function configureDependencies(): void
    {
        $this->clock  = new FrozenClock(new DateTimeImmutable('2021-07-10'));
        $this->signer = new Hmac\Sha256();
        $this->key    = InMemory::base64Encoded('qOIXmZRqZKY80qg0BjtCrskM6OK7gPOea8mz1H7h/dE=');
        $this->issuer = 'bar';
    }

    /** @return non-empty-string */
    private function createToken(): string
    {
        return (new JwtFacade(clock: $this->clock))->issue(
            $this->signer,
            $this->key,
            fn (Builder $builder, DateTimeImmutable $issuedAt): Builder => $builder
                    ->expiresAt($issuedAt->modify('+5 minutes'))
                    ->issuedBy($this->issuer),
        )->toString();
    }

    #[PHPUnit\Test]
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

    #[PHPUnit\Test]
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

    #[PHPUnit\Test]
    public function goodJwt(): void
    {
        $token = (new JwtFacade())->parse(
            $this->createToken(),
            new Constraint\SignedWith($this->signer, $this->key),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );

        self::assertInstanceOf(Token\Plain::class, $token);
    }

    #[PHPUnit\Test]
    public function badSigner(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signer mismatch');

        (new JwtFacade())->parse(
            $this->createToken(),
            new Constraint\SignedWith(new Hmac\Sha384(), $this->key),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );
    }

    #[PHPUnit\Test]
    public function badKey(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('Token signature mismatch');

        (new JwtFacade())->parse(
            $this->createToken(),
            new Constraint\SignedWith(
                $this->signer,
                InMemory::base64Encoded('czyPTpN595zVNSuvoNNlXCRFgXS2fHscMR36dGojaUE='),
            ),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );
    }

    #[PHPUnit\Test]
    public function badTime(): void
    {
        $token = $this->createToken();
        $this->clock->setTo($this->clock->now()->modify('+30 days'));

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token is expired');

        (new JwtFacade())->parse(
            $token,
            new Constraint\SignedWith($this->signer, $this->key),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );
    }

    #[PHPUnit\Test]
    public function badIssuer(): void
    {
        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token was not issued by the given issuers');

        (new JwtFacade())->parse(
            $this->createToken(),
            new Constraint\SignedWith($this->signer, $this->key),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy('xyz'),
        );
    }

    #[PHPUnit\Test]
    public function parserForNonUnencryptedTokens(): void
    {
        $this->expectException(AssertionError::class);

        (new JwtFacade(new UnsupportedParser()))->parse(
            'a.very-broken.token',
            new Constraint\SignedWith($this->signer, $this->key),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );
    }

    #[PHPUnit\Test]
    public function customPsrClock(): void
    {
        $clock = new class () implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable('2021-07-10');
            }
        };

        $facade = new JwtFacade(clock: $clock);

        $token = $facade->issue(
            $this->signer,
            $this->key,
            static fn (Builder $builder): Builder => $builder,
        );

        self::assertEquals(
            $token,
            $facade->parse(
                $token->toString(),
                new Constraint\SignedWith($this->signer, $this->key),
                new Constraint\StrictValidAt($clock),
            ),
        );
    }

    #[PHPUnit\Test]
    public function multipleKeys(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2023-11-19 22:10:00'));

        $token = (new JwtFacade())->parse(
            $this->createToken(),
            new Constraint\SignedWithOneInSet(
                new Constraint\SignedWithUntilDate(
                    $this->signer,
                    InMemory::base64Encoded('czyPTpN595zVNSuvoNNlXCRFgXS2fHscMR36dGojaUE='),
                    new DateTimeImmutable('2024-11-19 22:10:00'),
                    $clock,
                ),
                new Constraint\SignedWithUntilDate(
                    $this->signer,
                    $this->key,
                    new DateTimeImmutable('2025-11-19 22:10:00'),
                    $clock,
                ),
            ),
            new Constraint\StrictValidAt($this->clock),
            new Constraint\IssuedBy($this->issuer),
        );

        self::assertInstanceOf(Token\Plain::class, $token);
    }
}
