<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\SignedWith;
use Lcobucci\JWT\Validation\ValidAt;
use Lcobucci\JWT\Validation\Validator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use RuntimeException;

use function uniqid;

/**
 * @coversDefaultClass \Lcobucci\JWT\Token\SecureParser
 *
 * @uses  \Lcobucci\JWT\Token\Parser
 * @uses  \Lcobucci\JWT\Validation\Validator
 */
final class SecureParserTest extends TestCase
{
    /** @var Decoder&MockObject */
    private Decoder $decoder;
    private Validator $validator;
    /** @var SignedWith&MockObject */
    private $signedWith;
    /** @var ValidAt&MockObject */
    private $validAt;

    /** @before */
    public function createDependencies(): void
    {
        $this->decoder    = $this->createMock(Decoder::class);
        $this->validator  = new Validator();
        $this->signedWith = $this->createMock(SignedWith::class);
        $this->validAt    = $this->createMock(ValidAt::class);
    }

    private function createParser(): SecureParser
    {
        return new SecureParser($this->decoder, $this->validator);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     */
    public function parseMustRaiseExceptionWhenTokenDoesNotHaveThreeParts(): void
    {
        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('The JWT string must have two dots');

        $parser->parseJwt('', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     */
    public function parseMustRaiseExceptionWhenHeaderCannotBeDecoded(): void
    {
        $this->decoder->method('base64UrlDecode')
                      ->with('a')
                      ->willReturn('b');

        $this->decoder->method('jsonDecode')
                      ->with('b')
                      ->willThrowException(new RuntimeException('Nope'));

        $parser = $this->createParser();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Nope');

        $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidHeaders(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn('A very invalid header');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('headers must be an array');

        $parser->parseJwt('a.a.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\UnsupportedHeaderFound
     */
    public function parseMustRaiseExceptionWhenHeaderIsFromAnEncryptedToken(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturn(['enc' => 'AAA']);

        $parser = $this->createParser();

        $this->expectException(UnsupportedHeaderFound::class);
        $this->expectExceptionMessage('Encryption is not supported yet');

        $parser->parseJwt('a.a.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustRaiseExceptionWhenDealingWithInvalidClaims(): void
    {
        $this->decoder->method('jsonDecode')
                      ->willReturnOnConsecutiveCalls(['typ' => 'JWT'], 'A very invalid claim set');

        $parser = $this->createParser();

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('claims must be an array');

        $parser->parseJwt('a.a.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnAnUnsecuredTokenWhenSignatureIsNotInformed(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWT', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConfigureTypeToJWTWhenItIsMissing(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustNotChangeTypeWhenItIsConfigured(): void
    {
        $this->decoder->expects(self::exactly(2))
                      ->method('base64UrlDecode')
                      ->withConsecutive(['a'], ['b'])
                      ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
                      ->method('jsonDecode')
                      ->withConsecutive(['a_dec'], ['b_dec'])
                      ->willReturnOnConsecutiveCalls(
                          ['typ' => 'JWS', 'alg' => 'none'],
                          [RegisteredClaims::AUDIENCE => 'test']
                      );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWS', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseShouldReplicateClaimValueOnHeaderWhenNeeded(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none', RegisteredClaims::AUDIENCE => 'test'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsMissing(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.c', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnANonSignedTokenWhenSignatureAlgorithmIsNone(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.c', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers = new DataSet(['typ' => 'JWT', 'alg' => 'none'], 'a');
        $claims  = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals(Signature::fromEmptyData(), $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustReturnASignedTokenWhenSignatureIsInformed(): void
    {
        $this->decoder->expects(self::exactly(3))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'], ['c'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec', 'c_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $parser = $this->createParser();
        $token  = $parser->parseJwt('a.b.c', $this->signedWith, $this->validAt);

        self::assertInstanceOf(Plain::class, $token);

        $headers   = new DataSet(['typ' => 'JWT', 'alg' => 'HS256'], 'a');
        $claims    = new DataSet([RegisteredClaims::AUDIENCE => ['test']], 'b');
        $signature = new Signature('c_dec', 'c');

        self::assertEquals($headers, $token->headers());
        self::assertEquals($claims, $token->claims());
        self::assertEquals($signature, $token->signature());
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseMustConvertDateClaimsToObjects(): void
    {
        $data = [
            RegisteredClaims::ISSUED_AT => 1486930663,
            RegisteredClaims::EXPIRATION_TIME => '1486930757.023055',
        ];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data
            );

        $token = $this->createParser()->parseJwt('a.b.', $this->signedWith, $this->validAt);
        self::assertInstanceOf(Plain::class, $token);

        $claims = $token->claims();

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U', '1486930663'),
            $claims->get(RegisteredClaims::ISSUED_AT)
        );

        self::assertEquals(
            DateTimeImmutable::createFromFormat('U.u', '1486930757.023055'),
            $claims->get(RegisteredClaims::EXPIRATION_TIME)
        );
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     */
    public function parseShouldRaiseExceptionOnInvalidDate(): void
    {
        $data = [RegisteredClaims::ISSUED_AT => '14/10/2018 10:50:10.10 UTC'];

        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'HS256'],
                $data
            );

        $this->expectException(InvalidTokenStructure::class);
        $this->expectExceptionMessage('Value is not in the allowed date format: 14/10/2018 10:50:10.10 UTC');
        $this->createParser()->parseJwt('a.b.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Validation\RequiredConstraintsViolated
     * @uses \Lcobucci\JWT\Validation\ConstraintViolation
     */
    public function parseMustRaiseExceptionWhenSignatureIsInvalid(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $exceptionMessage = uniqid();
        $this->signedWith->expects(self::once())
            ->method('assert')
            ->with(self::isInstanceOf(Token::class))
            ->willThrowException(new ConstraintViolation($exceptionMessage));

        $parser = $this->createParser();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage($exceptionMessage);

        $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Validation\RequiredConstraintsViolated
     * @uses \Lcobucci\JWT\Validation\ConstraintViolation
     */
    public function parseMustRaiseExceptionWhenTimestampsAreInvalid(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $exceptionMessage = uniqid();
        $this->validAt->expects(self::once())
            ->method('assert')
            ->with(self::isInstanceOf(Token::class))
            ->willThrowException(new ConstraintViolation($exceptionMessage));

        $parser = $this->createParser();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage($exceptionMessage);

        $parser->parseJwt('a.b.', $this->signedWith, $this->validAt);
    }

    /**
     * @test
     *
     * @covers ::__construct
     * @covers ::parseJwt
     * @covers \Lcobucci\JWT\Token\InvalidTokenStructure
     *
     * @uses \Lcobucci\JWT\Token\Plain
     * @uses \Lcobucci\JWT\Token\Signature
     * @uses \Lcobucci\JWT\Token\DataSet
     * @uses \Lcobucci\JWT\Validation\RequiredConstraintsViolated
     * @uses \Lcobucci\JWT\Validation\ConstraintViolation
     */
    public function parseMustRaiseExceptionWhenOptionalConstraintFails(): void
    {
        $this->decoder->expects(self::exactly(2))
            ->method('base64UrlDecode')
            ->withConsecutive(['a'], ['b'])
            ->willReturnOnConsecutiveCalls('a_dec', 'b_dec');

        $this->decoder->expects(self::exactly(2))
            ->method('jsonDecode')
            ->withConsecutive(['a_dec'], ['b_dec'])
            ->willReturnOnConsecutiveCalls(
                ['typ' => 'JWT', 'alg' => 'none'],
                [RegisteredClaims::AUDIENCE => 'test']
            );

        $optionalConstraint = $this->createMock(Constraint::class);

        $exceptionMessage = uniqid();
        $optionalConstraint->expects(self::once())
            ->method('assert')
            ->with(self::isInstanceOf(Token::class))
            ->willThrowException(new ConstraintViolation($exceptionMessage));

        $parser = $this->createParser();

        $this->expectException(RequiredConstraintsViolated::class);
        $this->expectExceptionMessage($exceptionMessage);

        $parser->parseJwt('a.b.', $this->signedWith, $this->validAt, $optionalConstraint);
    }
}
