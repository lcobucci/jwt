<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

use function uniqid;

/**
 * @coversDefaultClass \Lcobucci\JWT\Token\TimedRequiringBuilder
 *
 * @uses \Lcobucci\JWT\Token\DataSet
 * @uses \Lcobucci\JWT\Token\Plain
 * @uses \Lcobucci\JWT\Token\Signature
 */
final class TimedRequiringBuilderTest extends TestCase
{
    /** @var Builder&MockObject */
    private $realBuilder;
    /** @var Signer&MockObject */
    private $signer;
    /** @var Signer\Key&MockObject */
    private $key;

    protected function setUp(): void
    {
        $this->realBuilder = $this->createMock(Builder::class);
        $this->signer      = $this->createMock(Signer::class);
        $this->key         = $this->createMock(Signer\Key::class);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::permittedFor
     * @covers ::expiresAt
     * @covers ::identifiedBy
     * @covers ::issuedAt
     * @covers ::issuedBy
     * @covers ::canOnlyBeUsedAfter
     * @covers ::relatedTo
     * @covers ::withHeader
     * @covers ::withClaim
     * @covers ::getToken
     */
    public function proxyCallsToRealBuilder(): void
    {
        $this->realBuilder->expects(self::once())
            ->method('permittedFor')
            ->with(self::identicalTo($permittedFor = uniqid()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('expiresAt')
            ->with(self::identicalTo($expiresAt = new DateTimeImmutable()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('identifiedBy')
            ->with(self::identicalTo($identifiedBy = uniqid()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('issuedAt')
            ->with(self::identicalTo($issuedAt = new DateTimeImmutable()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('issuedBy')
            ->with(self::identicalTo($issuedBy = uniqid()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('canOnlyBeUsedAfter')
            ->with(self::identicalTo($canOnlyBeUsedAfter = new DateTimeImmutable()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('relatedTo')
            ->with(self::identicalTo($relatedTo = uniqid()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('withHeader')
            ->with(
                self::identicalTo($withHeaderName = uniqid()),
                self::identicalTo($withHeaderValue = uniqid())
            )
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('withClaim')
            ->with(
                self::identicalTo($withClaimName = uniqid()),
                self::identicalTo($withClaimValue = uniqid())
            )
            ->willReturnSelf();
        $expectedToken = new Plain(
            new DataSet([], ''),
            new DataSet([], ''),
            new Signature('', '')
        );
        $this->realBuilder->expects(self::once())
            ->method('getToken')
            ->with(
                self::identicalTo($this->signer),
                self::identicalTo($this->key)
            )
            ->willReturn($expectedToken);

        $actualToken = (new TimedRequiringBuilder($this->realBuilder))
            ->permittedFor($permittedFor)
            ->expiresAt($expiresAt)
            ->identifiedBy($identifiedBy)
            ->issuedAt($issuedAt)
            ->issuedBy($issuedBy)
            ->canOnlyBeUsedAfter($canOnlyBeUsedAfter)
            ->relatedTo($relatedTo)
            ->withHeader($withHeaderName, $withHeaderValue)
            ->withClaim($withClaimName, $withClaimValue)
            ->getToken($this->signer, $this->key);

        self::assertSame($expectedToken, $actualToken);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\TimeRequired::expiresAtRequired
     * @covers ::__construct
     * @covers ::getToken
     */
    public function expiresAtMustBeCalledToIssueTheToken(): void
    {
        $this->expectException(TimeRequired::class);
        $this->expectExceptionMessage('expiresAt');

        (new TimedRequiringBuilder($this->realBuilder))
            ->getToken($this->signer, $this->key);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\TimeRequired::issuedAtRequired
     * @covers ::__construct
     * @covers ::expiresAt
     * @covers ::getToken
     */
    public function issuedAtMustBeCalledToIssueTheToken(): void
    {
        $this->realBuilder->expects(self::once())
            ->method('expiresAt')
            ->with(self::identicalTo($expiresAt = new DateTimeImmutable()))
            ->willReturnSelf();

        $this->expectException(TimeRequired::class);
        $this->expectExceptionMessage('issuedAt');

        (new TimedRequiringBuilder($this->realBuilder))
            ->expiresAt($expiresAt)
            ->getToken($this->signer, $this->key);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Token\TimeRequired::canOnlyBeUsedAfterRequired
     * @covers ::__construct
     * @covers ::expiresAt
     * @covers ::issuedAt
     * @covers ::getToken
     */
    public function canOnlyBeUsedAfterMustBeCalledToIssueTheToken(): void
    {
        $this->realBuilder->expects(self::once())
            ->method('expiresAt')
            ->with(self::identicalTo($expiresAt = new DateTimeImmutable()))
            ->willReturnSelf();
        $this->realBuilder->expects(self::once())
            ->method('issuedAt')
            ->with(self::identicalTo($issuedAt = new DateTimeImmutable()))
            ->willReturnSelf();

        $this->expectException(TimeRequired::class);
        $this->expectExceptionMessage('canOnlyBeUsedAfter');

        (new TimedRequiringBuilder($this->realBuilder))
            ->expiresAt($expiresAt)
            ->issuedAt($issuedAt)
            ->getToken($this->signer, $this->key);
    }
}
