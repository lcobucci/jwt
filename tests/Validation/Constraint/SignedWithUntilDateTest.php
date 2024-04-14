<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Validation\Constraint;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Encoding\UnifyAudience;
use Lcobucci\JWT\Encoding\UnixTimestampDates;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Tests\Signer\FakeSigner;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\SignedWithUntilDate;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

#[PHPUnit\CoversClass(SignedWithUntilDate::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\UsesClass(DataSet::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(Plain::class)]
#[PHPUnit\UsesClass(Signature::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(JwtFacade::class)]
#[PHPUnit\UsesClass(ChainedFormatter::class)]
#[PHPUnit\UsesClass(JoseEncoder::class)]
#[PHPUnit\UsesClass(UnifyAudience::class)]
#[PHPUnit\UsesClass(UnixTimestampDates::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
#[PHPUnit\UsesClass(Builder::class)]
#[PHPUnit\UsesClass(Token\Parser::class)]
final class SignedWithUntilDateTest extends ConstraintTestCase
{
    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenConstraintUsageIsNotValidAnymore(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2023-11-19 22:45:10'));

        $constraint = new SignedWithUntilDate(
            new FakeSigner('1'),
            InMemory::plainText('a'),
            $clock->now()->modify('-1 hour'),
            $clock,
        );

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('This constraint was only usable until 2023-11-19T21:45:10+00:00');

        $constraint->assert($this->issueToken(new FakeSigner('1'), InMemory::plainText('a')));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenTokenIsNotAPlainToken(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2023-11-19 22:45:10'));

        $constraint = new SignedWithUntilDate(new FakeSigner('1'), InMemory::plainText('a'), $clock->now(), $clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('You should pass a plain token');

        $constraint->assert($this->createMock(Token::class));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSignerIsNotTheSame(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2023-11-19 22:45:10'));
        $key   = InMemory::plainText('a');

        $constraint = new SignedWithUntilDate(new FakeSigner('1'), $key, $clock->now(), $clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signer mismatch');

        $constraint->assert($this->issueToken(new FakeSigner('2'), $key));
    }

    #[PHPUnit\Test]
    public function assertShouldRaiseExceptionWhenSignatureIsInvalid(): void
    {
        $clock  = new FrozenClock(new DateTimeImmutable('2023-11-19 22:45:10'));
        $signer = new FakeSigner('1');

        $constraint = new SignedWithUntilDate($signer, InMemory::plainText('a'), $clock->now(), $clock);

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage('Token signature mismatch');

        $constraint->assert($this->issueToken($signer, InMemory::plainText('b')));
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionWhenSignatureIsValid(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('2023-11-19 22:45:10'));

        $signer = new FakeSigner('1');
        $key    = InMemory::plainText('a');

        $constraint = new SignedWithUntilDate($signer, $key, $clock->now(), $clock);
        $constraint->assert($this->issueToken($signer, $key));

        $this->addToAssertionCount(1);
    }

    #[PHPUnit\Test]
    public function clockShouldBeOptional(): void
    {
        $signer = new FakeSigner('1');
        $key    = InMemory::plainText('a');

        $constraint = new SignedWithUntilDate($signer, $key, new DateTimeImmutable('+10 seconds'));
        $constraint->assert($this->issueToken($signer, $key));

        $this->addToAssertionCount(1);
    }
}
