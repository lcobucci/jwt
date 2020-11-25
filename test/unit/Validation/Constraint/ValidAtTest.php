<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\ConstraintViolation;

/** @coversDefaultClass \Lcobucci\JWT\Validation\Constraint\ValidAt */
final class ValidAtTest extends ConstraintTestCase
{
    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::assert
     */
    public function assertIsAProxyToLooseValidAt(): void
    {
        $clock = new FrozenClock(new DateTimeImmutable());

        $claims = [
            RegisteredClaims::ISSUED_AT => $clock->now(),
            RegisteredClaims::NOT_BEFORE => $clock->now()->modify('+5 seconds'),
            RegisteredClaims::EXPIRATION_TIME => $clock->now()->modify('15 seconds'),
        ];

        // @phpstan-ignore-next-line
        $constraint = new ValidAt($clock, new DateInterval('PT1S'));

        $clock->setTo($clock->now()->modify('+4 seconds'));
        $constraint->assert($this->buildToken($claims));
        $this->addToAssertionCount(1);

        $this->expectException(ConstraintViolation::class);

        $clock->setTo($clock->now()->modify('+20 seconds'));
        $constraint->assert($this->buildToken($claims));
    }
}
