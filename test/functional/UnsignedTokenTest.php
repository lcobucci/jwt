<?php
declare(strict_types=1);

namespace Lcobucci\JWT\FunctionalTests;

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use PHPUnit\Framework\TestCase;

use function assert;

/**
 * @covers \Lcobucci\JWT\Configuration
 * @covers \Lcobucci\JWT\Encoding\JoseEncoder
 * @covers \Lcobucci\JWT\Encoding\ChainedFormatter
 * @covers \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
 * @covers \Lcobucci\JWT\Encoding\UnifyAudience
 * @covers \Lcobucci\JWT\Token\Builder
 * @covers \Lcobucci\JWT\Token\Parser
 * @covers \Lcobucci\JWT\Token\Plain
 * @covers \Lcobucci\JWT\Token\DataSet
 * @covers \Lcobucci\JWT\Token\Signature
 * @covers \Lcobucci\JWT\Signer\None
 * @covers \Lcobucci\JWT\Signer\Key\InMemory
 * @covers \Lcobucci\JWT\Validation\RequiredConstraintsViolated
 * @covers \Lcobucci\JWT\Validation\Validator
 * @covers \Lcobucci\JWT\Validation\Constraint\IssuedBy
 * @covers \Lcobucci\JWT\Validation\Constraint\PermittedFor
 * @covers \Lcobucci\JWT\Validation\Constraint\IdentifiedBy
 * @covers \Lcobucci\JWT\Validation\Constraint\LooseValidAt
 */
class UnsignedTokenTest extends TestCase
{
    public const CURRENT_TIME = 100000;

    private Configuration $config;

    /** @before */
    public function createConfiguration(): void
    {
        $this->config = Configuration::forUnsecuredSigner();
    }

    /** @test */
    public function builderCanGenerateAToken(): Token
    {
        $user    = ['name' => 'testing', 'email' => 'testing@abc.com'];
        $builder = $this->config->builder();

        $expiration = new DateTimeImmutable('@' . (self::CURRENT_TIME + 3000));

        $token = $builder->identifiedBy('1')
                         ->permittedFor('http://client.abc.com')
                         ->issuedBy('http://api.abc.com')
                         ->expiresAt($expiration)
                         ->withClaim('user', $user)
                         ->getToken($this->config->signer(), $this->config->signingKey());

        self::assertEquals(new Token\Signature('', ''), $token->signature());
        self::assertEquals(['http://client.abc.com'], $token->claims()->get(Token\RegisteredClaims::AUDIENCE));
        self::assertEquals('http://api.abc.com', $token->claims()->get(Token\RegisteredClaims::ISSUER));
        self::assertSame($expiration, $token->claims()->get(Token\RegisteredClaims::EXPIRATION_TIME));
        self::assertEquals($user, $token->claims()->get('user'));

        return $token;
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function parserCanReadAToken(Token $generated): void
    {
        $read = $this->config->parser()->parse($generated->toString());
        assert($read instanceof Token\Plain);

        self::assertEquals($generated, $read);
        self::assertEquals('testing', $read->claims()->get('user')['name']);
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function tokenValidationShouldPassWhenEverythingIsFine(Token $generated): void
    {
        $clock = new FrozenClock(new DateTimeImmutable('@' . self::CURRENT_TIME));

        $constraints = [
            new IdentifiedBy('1'),
            new PermittedFor('http://client.abc.com'),
            new IssuedBy('http://issuer.abc.com', 'http://api.abc.com'),
            new LooseValidAt($clock),
        ];

        self::assertTrue($this->config->validator()->validate($generated, ...$constraints));
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function tokenValidationShouldAllowCustomConstraint(Token $generated): void
    {
        self::assertTrue($this->config->validator()->validate($generated, $this->validUserConstraint()));
    }

    /**
     * @test
     * @depends builderCanGenerateAToken
     */
    public function tokenAssertionShouldRaiseExceptionWhenOneOfTheConstraintsFails(Token $generated): void
    {
        $constraints = [
            new IdentifiedBy('1'),
            new IssuedBy('http://issuer.abc.com'),
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
