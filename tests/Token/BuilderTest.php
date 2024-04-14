<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\RegisteredClaimGiven;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Token\Signature;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SplObjectStorage;

#[PHPUnit\CoversClass(Builder::class)]
#[PHPUnit\CoversClass(RegisteredClaimGiven::class)]
#[PHPUnit\UsesClass(MicrosecondBasedDateConversion::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(Plain::class)]
#[PHPUnit\UsesClass(Signature::class)]
#[PHPUnit\UsesClass(DataSet::class)]
final class BuilderTest extends TestCase
{
    private Encoder&MockObject $encoder;
    private Signer&MockObject $signer;

    #[PHPUnit\Before]
    public function initializeDependencies(): void
    {
        $this->encoder = $this->createMock(Encoder::class);
        $this->signer  = $this->createMock(Signer::class);
        $this->signer->method('algorithmId')->willReturn('RS256');
    }

    #[PHPUnit\Test]
    public function withClaimShouldRaiseExceptionWhenTryingToConfigureARegisteredClaim(): void
    {
        $builder = new Builder($this->encoder, new MicrosecondBasedDateConversion());

        $this->expectException(RegisteredClaimGiven::class);
        $this->expectExceptionMessage(
            'Builder#withClaim() is meant to be used for non-registered claims, '
            . 'check the documentation on how to set claim "iss"',
        );

        $builder->withClaim(RegisteredClaims::ISSUER, 'me');
    }

    #[PHPUnit\Test]
    public function getTokenShouldReturnACompletelyConfigureToken(): void
    {
        $issuedAt   = new DateTimeImmutable('@1487285080');
        $notBefore  = DateTimeImmutable::createFromFormat('U.u', '1487285080.000123');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');

        self::assertInstanceOf(DateTimeImmutable::class, $notBefore);
        self::assertInstanceOf(DateTimeImmutable::class, $expiration);

        $this->encoder->expects(self::exactly(2))
                     ->method('jsonEncode')
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects(self::exactly(3))
                      ->method('base64UrlEncode')
                      ->willReturnArgument(0);

        $this->signer->expects($this->once())
            ->method('sign')
            ->with('1.2')
            ->willReturn('3');

        $builder = new Builder($this->encoder, new MicrosecondBasedDateConversion());
        $token   = $builder->identifiedBy('123456')
                           ->issuedBy('https://issuer.com')
                           ->issuedAt($issuedAt)
                           ->canOnlyBeUsedAfter($notBefore)
                           ->expiresAt($expiration)
                           ->relatedTo('subject')
                           ->permittedFor('test1')
                           ->permittedFor('test2')
                           ->permittedFor('test2') // should not be added since it's duplicated
                           ->withClaim('test', 123)
                           ->withHeader('userId', 2)
                           ->getToken($this->signer, InMemory::plainText('123'));

        self::assertSame('JWT', $token->headers()->get('typ'));
        self::assertSame('RS256', $token->headers()->get('alg'));
        self::assertSame(2, $token->headers()->get('userId'));
        self::assertSame(123, $token->claims()->get('test'));
        self::assertSame($issuedAt, $token->claims()->get(RegisteredClaims::ISSUED_AT));
        self::assertSame($notBefore, $token->claims()->get(RegisteredClaims::NOT_BEFORE));
        self::assertSame($expiration, $token->claims()->get(RegisteredClaims::EXPIRATION_TIME));
        self::assertSame('123456', $token->claims()->get(RegisteredClaims::ID));
        self::assertSame('https://issuer.com', $token->claims()->get(RegisteredClaims::ISSUER));
        self::assertSame('subject', $token->claims()->get(RegisteredClaims::SUBJECT));
        self::assertSame(['test1', 'test2'], $token->claims()->get(RegisteredClaims::AUDIENCE));
        self::assertSame('3', $token->signature()->toString());
    }

    #[PHPUnit\Test]
    public function immutability(): void
    {
        $map           = new SplObjectStorage();
        $builder       = new Builder($this->encoder, new MicrosecondBasedDateConversion());
        $map[$builder] = true;
        $builder       = $builder->identifiedBy('123456');
        $map[$builder] = true;
        $builder       = $builder->issuedBy('https://issuer.com');
        $map[$builder] = true;
        $builder       = $builder->issuedAt(new DateTimeImmutable());
        $map[$builder] = true;
        $builder       = $builder->canOnlyBeUsedAfter(new DateTimeImmutable());
        $map[$builder] = true;
        $builder       = $builder->expiresAt(new DateTimeImmutable());
        $map[$builder] = true;
        $builder       = $builder->relatedTo('subject');
        $map[$builder] = true;
        $builder       = $builder->permittedFor('test1');
        $map[$builder] = true;
        $builder       = $builder->withClaim('test', 123);
        $map[$builder] = true;
        $builder       = $builder->withHeader('userId', 2);
        $map[$builder] = true;

        self::assertCount(10, $map);
    }
}
