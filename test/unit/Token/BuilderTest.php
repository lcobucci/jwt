<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Jose\Parsing\Encoder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class BuilderTest extends TestCase
{
    /** @var Encoder&MockObject */
    private Encoder $encoder;

    /** @var Signer&MockObject */
    private Signer $signer;

    /**
     * @before
     */
    public function initializeDependencies(): void
    {
        $this->encoder = $this->createMock(Encoder::class);
        $this->signer  = $this->createMock(Signer::class);
        $this->signer->method('getAlgorithmId')->willReturn('RS256');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     */
    public function withClaimShouldRaiseExceptionWhenTryingToConfigureARegisteredClaim(): void
    {
        $builder = new Builder($this->encoder);

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('You should use the correct methods to set registered claims');

        $builder->withClaim(RegisteredClaims::ISSUER, 'me');
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     * @covers \Lcobucci\JWT\Token\Builder::getToken
     * @covers \Lcobucci\JWT\Token\Builder::encode
     * @covers \Lcobucci\JWT\Token\Builder::formatClaims
     * @covers \Lcobucci\JWT\Token\Builder::convertDate
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function claimsMustBeFormattedWhileEncoding(): void
    {
        $issuedAt   = new DateTimeImmutable('@1487285080');
        $notBefore  = DateTimeImmutable::createFromFormat('U.u', '1487285080.000123');
        $expiration = DateTimeImmutable::createFromFormat('U.u', '1487285080.123456');

        self::assertInstanceOf(DateTimeImmutable::class, $notBefore);
        self::assertInstanceOf(DateTimeImmutable::class, $expiration);

        $headers = ['typ' => 'JWT', 'alg' => 'RS256', 'userId' => 2];
        $claims  = [
            RegisteredClaims::ID => '123456',
            RegisteredClaims::ISSUER => 'https://issuer.com',
            RegisteredClaims::ISSUED_AT => 1487285080,
            RegisteredClaims::NOT_BEFORE => '1487285080.000123',
            RegisteredClaims::EXPIRATION_TIME => '1487285080.123456',
            RegisteredClaims::SUBJECT => 'subject',
            RegisteredClaims::AUDIENCE => 'test1',
            'test' => 123,
        ];

        $this->signer->method('sign')->willReturn('testing');

        $this->encoder->expects(self::exactly(2))
                     ->method('jsonEncode')
                      ->withConsecutive([self::identicalTo($headers)], [self::identicalTo($claims)])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects(self::exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['testing'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = new Builder($this->encoder);

        $builder->identifiedBy('123456')
                ->issuedBy('https://issuer.com')
                ->issuedAt($issuedAt)
                ->canOnlyBeUsedAfter($notBefore)
                ->expiresAt($expiration)
                ->relatedTo('subject')
                ->permittedFor('test1')
                ->withClaim('test', 123)
                ->withHeader('userId', 2)
                ->getToken($this->signer, new Key('123'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     * @covers \Lcobucci\JWT\Token\Builder::encode
     * @covers \Lcobucci\JWT\Token\Builder::formatClaims
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     *
     * @uses \Lcobucci\JWT\Token\Builder::getToken
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function audienceShouldBeFormattedAsArrayWhenMultipleValuesAreUsed(): void
    {
        $headers = ['typ' => 'JWT', 'alg' => 'RS256'];
        $claims  = [RegisteredClaims::AUDIENCE => ['test1', 'test2', 'test3']];

        $this->signer->method('sign')->willReturn('testing');

        $this->encoder->expects(self::exactly(2))
                     ->method('jsonEncode')
                      ->withConsecutive([self::identicalTo($headers)], [self::identicalTo($claims)])
                      ->willReturnOnConsecutiveCalls('1', '2');

        $this->encoder->expects(self::exactly(3))
                      ->method('base64UrlEncode')
                      ->withConsecutive(['1'], ['2'], ['testing'])
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = new Builder($this->encoder);

        $builder->permittedFor('test1', 'test2', 'test3')
                ->permittedFor('test2') // should not be added since it's duplicated
                ->getToken($this->signer, new Key('123'));
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\Builder::__construct
     * @covers \Lcobucci\JWT\Token\Builder::getToken
     * @covers \Lcobucci\JWT\Token\Builder::encode
     * @covers \Lcobucci\JWT\Token\Builder::formatClaims
     * @covers \Lcobucci\JWT\Token\Builder::convertDate
     * @covers \Lcobucci\JWT\Token\Builder::withClaim
     * @covers \Lcobucci\JWT\Token\Builder::withHeader
     * @covers \Lcobucci\JWT\Token\Builder::identifiedBy
     * @covers \Lcobucci\JWT\Token\Builder::setClaim
     * @covers \Lcobucci\JWT\Token\Builder::issuedBy
     * @covers \Lcobucci\JWT\Token\Builder::issuedAt
     * @covers \Lcobucci\JWT\Token\Builder::relatedTo
     * @covers \Lcobucci\JWT\Token\Builder::canOnlyBeUsedAfter
     * @covers \Lcobucci\JWT\Token\Builder::expiresAt
     * @covers \Lcobucci\JWT\Token\Builder::permittedFor
     *
     * @uses \Lcobucci\JWT\Signer\Key
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
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
                      ->willReturnOnConsecutiveCalls('1', '2', '3');

        $builder = new Builder($this->encoder);
        $token   = $builder->identifiedBy('123456')
                           ->issuedBy('https://issuer.com')
                           ->issuedAt($issuedAt)
                           ->canOnlyBeUsedAfter($notBefore)
                           ->expiresAt($expiration)
                           ->relatedTo('subject')
                           ->permittedFor('test1')
                           ->permittedFor('test2')
                           ->withClaim('test', 123)
                           ->withHeader('userId', 2)
                           ->getToken($this->signer, new Key('123'));

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
}
