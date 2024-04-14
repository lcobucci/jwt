<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\SodiumBase64Polyfill;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\TestCase;

use function assert;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\CoversClass(Encoding\JoseEncoder::class)]
#[PHPUnit\CoversClass(Encoding\ChainedFormatter::class)]
#[PHPUnit\CoversClass(Encoding\MicrosecondBasedDateConversion::class)]
#[PHPUnit\CoversClass(Encoding\UnifyAudience::class)]
#[PHPUnit\CoversClass(Token\Builder::class)]
#[PHPUnit\CoversClass(Token\Parser::class)]
#[PHPUnit\CoversClass(Token\Plain::class)]
#[PHPUnit\CoversClass(Token\DataSet::class)]
#[PHPUnit\CoversClass(Token\Signature::class)]
#[PHPUnit\CoversClass(InMemory::class)]
#[PHPUnit\CoversClass(SodiumBase64Polyfill::class)]
#[PHPUnit\CoversClass(ConstraintViolation::class)]
#[PHPUnit\CoversClass(RequiredConstraintsViolated::class)]
#[PHPUnit\CoversClass(Validator::class)]
#[PHPUnit\CoversClass(IssuedBy::class)]
#[PHPUnit\CoversClass(PermittedFor::class)]
#[PHPUnit\CoversClass(IdentifiedBy::class)]
#[PHPUnit\CoversClass(LooseValidAt::class)]
class UnsignedTokenTest extends TestCase
{
    public const CURRENT_TIME = 100000;

    private Configuration $config;

    #[PHPUnit\Before]
    public function createConfiguration(): void
    {
        $this->config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
    }

    #[PHPUnit\Test]
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $expiration = new DateTimeImmutable('@' . (self::CURRENT_TIME + 3000));

        $token = $builder->identifiedBy('1')
                         ->permittedFor('https://client.abc.com')
                         ->issuedBy('https://api.abc.com')
                         ->expiresAt($expiration)
                         ->withClaim('user', $user)
                         ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertEquals(new Token\Signature('private', 'cHJpdmF0ZQ'), $token->signature());
        self::assertEquals(['https://client.abc.com'], $token->claims()->get(Token\RegisteredClaims::AUDIENCE));
        self::assertSame('https://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertEquals($expiration, $token->claims()->get(Token\RegisteredClaims::EXPIRATION_TIME));
        self::assertEquals($user, $token->claims()->get('user'));

        return $token;
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function parserCanReadAToken(Token $generated): void
    {
        $read = $this->config->parser()->parse($generated->toString());
        assert($read instanceof Token\Plain);

        self::assertEquals($generated, $read);
        self::assertSame('testing', $read->claims()->get('user')['name']);
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function tokenValidationShouldPassWhenEverythingIsFine(Token $generated): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('@' . self::CURRENT_TIME));

        $constraints = [
            new IdentifiedBy('1'),
            new PermittedFor('https://client.abc.com'),
            new IssuedBy('https://issuer.abc.com', 'https://api.abc.com'),
            new LooseValidAt($clock),
        ];

        self::assertTrue($this->config->validator()->validate($generated, ...$constraints));
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function tokenValidationShouldAllowCustomConstraint(Token $generated): void
    {
        self::assertTrue($this->config->validator()->validate($generated, $this->validUserConstraint()));
    }

    #[PHPUnit\Test]
    #[PHPUnit\Depends('builderCanGenerateAToken')]
    public function tokenAssertionShouldRaiseExceptionWhenOneOfTheConstraintsFails(Token $generated): void
    {
        $constraints = [
            new IdentifiedBy('1'),
            new IssuedBy('https://issuer.abc.com'),
        ];

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage('The token violates some mandatory constraints');

        $this->config->validator()->assert($generated, ...$constraints);
    }

    private function validUserConstraint(): Constraint
    {
        return new class () implements Constraint
        {
            public function assert(Token $token): void
            {
                if (! $token instanceof Token\Plain) {
                    throw new ConstraintViolation();
                }

                $claims = $token->claims();

                if (! $claims->has('user')) {
                    throw new ConstraintViolation();
                }

                $name  = $claims->get('user')['name'] ?? '';
                $email = $claims->get('user')['email'] ?? '';

                if ($name === '' || $email === '') {
                    throw new ConstraintViolation();
                }
            }
        };
    }
}
