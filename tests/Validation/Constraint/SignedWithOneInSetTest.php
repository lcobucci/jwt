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
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\SignedWithOneInSet;
use Lcobucci\JWT\Validation\Constraint\SignedWithUntilDate;
use Lcobucci\JWT\Validation\ConstraintViolation;
use PHPUnit\Framework\Attributes as PHPUnit;

use const PHP_EOL;

#[PHPUnit\CoversClass(SignedWithOneInSet::class)]
#[PHPUnit\CoversClass(SignedWithUntilDate::class)]
#[PHPUnit\CoversClass(SignedWith::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(JwtFacade::class)]
#[PHPUnit\UsesClass(ChainedFormatter::class)]
#[PHPUnit\UsesClass(JoseEncoder::class)]
#[PHPUnit\UsesClass(UnifyAudience::class)]
#[PHPUnit\UsesClass(UnixTimestampDates::class)]
#[PHPUnit\UsesClass(SodiumBase64Polyfill::class)]
#[PHPUnit\UsesClass(Builder::class)]
#[PHPUnit\UsesClass(DataSet::class)]
#[PHPUnit\UsesClass(Plain::class)]
#[PHPUnit\UsesClass(Signature::class)]
#[PHPUnit\UsesClass(Parser::class)]
final class SignedWithOneInSetTest extends ConstraintTestCase
{
    #[PHPUnit\Test]
    public function exceptionShouldBeRaisedWhenSignatureIsNotVerifiedByAllConstraints(): void
    {
        $clock  = new FrozenClock(new DateTimeImmutable('2023-11-19 22:20:00'));
        $signer = new FakeSigner('123');

        $constraint = new SignedWithOneInSet(
            new SignedWithUntilDate($signer, InMemory::plainText('b'), $clock->now(), $clock),
            new SignedWithUntilDate($signer, InMemory::plainText('c'), $clock->now()->modify('-2 minutes'), $clock),
        );

        $this->expectException(ConstraintViolation::class);
        $this->expectExceptionMessage(
            'It was not possible to verify the signature of the token, reasons:'
            . PHP_EOL . '- Token signature mismatch'
            . PHP_EOL . '- This constraint was only usable until 2023-11-19T22:18:00+00:00',
        );

        $token = $this->issueToken($signer, InMemory::plainText('a'));
        $constraint->assert($token);
    }

    #[PHPUnit\Test]
    public function assertShouldNotRaiseExceptionsWhenSignatureIsVerifiedByAtLeastOneConstraint(): void
    {
        $clock  = new FrozenClock(new DateTimeImmutable('2023-11-19 22:20:00'));
        $signer = new FakeSigner('123');

        $constraint = new SignedWithOneInSet(
            new SignedWithUntilDate($signer, InMemory::plainText('b'), $clock->now(), $clock),
            new SignedWithUntilDate($signer, InMemory::plainText('c'), $clock->now()->modify('-2 minutes'), $clock),
            new SignedWithUntilDate($signer, InMemory::plainText('a'), $clock->now(), $clock),
        );

        $token = $this->issueToken($signer, InMemory::plainText('a'));
        $constraint->assert($token);

        $this->addToAssertionCount(1);
    }
}
