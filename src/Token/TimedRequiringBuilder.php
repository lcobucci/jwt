<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

final class TimedRequiringBuilder implements Builder
{
    private Builder $realBuilder;
    private bool $expiresAtCalled          = false;
    private bool $issuedAtCalled           = false;
    private bool $canOnlyBeUsedAfterCalled = false;

    public function __construct(Builder $realBuilder)
    {
        $this->realBuilder = $realBuilder;
    }

    public function permittedFor(string ...$audiences): Builder
    {
        $this->realBuilder->permittedFor(...$audiences);

        return $this;
    }

    public function expiresAt(DateTimeImmutable $expiration): Builder
    {
        $this->realBuilder->expiresAt($expiration);
        $this->expiresAtCalled = true;

        return $this;
    }

    public function identifiedBy(string $id): Builder
    {
        $this->realBuilder->identifiedBy($id);

        return $this;
    }

    public function issuedAt(DateTimeImmutable $issuedAt): Builder
    {
        $this->realBuilder->issuedAt($issuedAt);
        $this->issuedAtCalled = true;

        return $this;
    }

    public function issuedBy(string $issuer): Builder
    {
        $this->realBuilder->issuedBy($issuer);

        return $this;
    }

    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): Builder
    {
        $this->realBuilder->canOnlyBeUsedAfter($notBefore);
        $this->canOnlyBeUsedAfterCalled = true;

        return $this;
    }

    public function relatedTo(string $subject): Builder
    {
        $this->realBuilder->relatedTo($subject);

        return $this;
    }

    /** @inheritdoc */
    public function withHeader(string $name, $value): Builder
    {
        $this->realBuilder->withHeader($name, $value);

        return $this;
    }

    /** @inheritdoc */
    public function withClaim(string $name, $value): Builder
    {
        $this->realBuilder->withClaim($name, $value);

        return $this;
    }

    public function getToken(Signer $signer, Key $key): Plain
    {
        if (! $this->expiresAtCalled) {
            throw TimeRequired::expiresAtRequired();
        }

        if (! $this->issuedAtCalled) {
            throw TimeRequired::issuedAtRequired();
        }

        if (! $this->canOnlyBeUsedAfterCalled) {
            throw TimeRequired::canOnlyBeUsedAfterRequired();
        }

        return $this->realBuilder->getToken($signer, $key);
    }
}
