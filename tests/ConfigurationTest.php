<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Token\Builder as BuilderImpl;
use Lcobucci\JWT\Token\Parser as ParserImpl;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers ::__construct
 * @coversDefaultClass \Lcobucci\JWT\Configuration
 *
 * @uses \Lcobucci\JWT\Encoding\ChainedFormatter
 * @uses \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
 * @uses \Lcobucci\JWT\Encoding\UnifyAudience
 * @uses \Lcobucci\JWT\Signer\Key\InMemory
 * @uses \Lcobucci\JWT\Signer\None
 * @uses \Lcobucci\JWT\Token\Builder
 * @uses \Lcobucci\JWT\Token\Parser
 * @uses \Lcobucci\JWT\Validation\Validator
 */
final class ConfigurationTest extends TestCase
{
    private Parser&MockObject $parser;
    private Signer&MockObject $signer;
    private Encoder&MockObject $encoder;
    private Decoder&MockObject $decoder;
    private Validator&MockObject $validator;
    private Constraint&MockObject $validationConstraints;

    /** @before */
    public function createDependencies(): void
    {
        $this->signer                = $this->createMock(Signer::class);
        $this->encoder               = $this->createMock(Encoder::class);
        $this->decoder               = $this->createMock(Decoder::class);
        $this->parser                = $this->createMock(Parser::class);
        $this->validator             = $this->createMock(Validator::class);
        $this->validationConstraints = $this->createMock(Constraint::class);
    }

    /**
     * @test
     *
     * @covers ::forAsymmetricSigner
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     */
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $signingKey      = InMemory::plainText('private');
        $verificationKey = InMemory::plainText('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertSame($this->signer, $config->signer());
        self::assertSame($signingKey, $config->signingKey());
        self::assertSame($verificationKey, $config->verificationKey());
    }

    /**
     * @test
     *
     * @covers ::forSymmetricSigner
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     */
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = InMemory::plainText('private');
        $config = Configuration::forSymmetricSigner($this->signer, $key);

        self::assertSame($this->signer, $config->signer());
        self::assertSame($key, $config->signingKey());
        self::assertSame($key, $config->verificationKey());
    }

    /**
     * @test
     *
     * @covers ::forUnsecuredSigner
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     */
    public function forUnsecuredSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = InMemory::empty();
        $config = Configuration::forUnsecuredSigner();

        self::assertInstanceOf(None::class, $config->signer());
        self::assertEquals($key, $config->signingKey());
        self::assertEquals($key, $config->verificationKey());
    }

    /**
     * @test
     *
     * @covers ::builder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function builderShouldCreateABuilderWithDefaultEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forUnsecuredSigner();
        $builder = $config->builder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertNotEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
        self::assertEquals(new BuilderImpl(new JoseEncoder(), ChainedFormatter::default()), $builder);
    }

    /**
     * @test
     *
     * @covers ::builder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function builderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forUnsecuredSigner($this->encoder);
        $builder = $config->builder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
    }

    /**
     * @test
     *
     * @covers ::builder
     * @covers ::setBuilderFactory
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function builderShouldUseBuilderFactoryWhenThatIsConfigured(): void
    {
        $builder = $this->createMock(Builder::class);

        $config = Configuration::forUnsecuredSigner();
        $config->setBuilderFactory(
            static function () use ($builder): Builder {
                return $builder;
            },
        );
        self::assertSame($builder, $config->builder());
    }

    /**
     * @test
     *
     * @covers ::parser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function parserShouldReturnAParserWithDefaultDecoder(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $parser = $config->parser();

        self::assertNotEquals(new ParserImpl($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::parser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function parserShouldReturnAParserWithCustomizedDecoder(): void
    {
        $config = Configuration::forUnsecuredSigner(decoder: $this->decoder);
        $parser = $config->parser();

        self::assertEquals(new ParserImpl($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::parser
     * @covers ::setParser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function parserShouldNotCreateAnInstanceIfItWasConfigured(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setParser($this->parser);

        self::assertSame($this->parser, $config->parser());
    }

    /**
     * @test
     *
     * @covers ::validator
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function validatorShouldReturnTheDefaultWhenItWasNotConfigured(): void
    {
        $config    = Configuration::forUnsecuredSigner();
        $validator = $config->validator();

        self::assertNotSame($this->validator, $validator);
    }

    /**
     * @test
     *
     * @covers ::validator
     * @covers ::setValidator
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function validatorShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidator($this->validator);

        self::assertSame($this->validator, $config->validator());
    }

    /**
     * @test
     *
     * @covers ::validationConstraints
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function validationConstraintsShouldReturnAnEmptyArrayWhenItWasNotConfigured(): void
    {
        $config = Configuration::forUnsecuredSigner();

        self::assertSame([], $config->validationConstraints());
    }

    /**
     * @test
     *
     * @covers ::validationConstraints
     * @covers ::setValidationConstraints
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function validationConstraintsShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints($this->validationConstraints);

        self::assertSame([$this->validationConstraints], $config->validationConstraints());
    }

    /**
     * @test
     *
     * @covers ::builder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     */
    public function customClaimFormatterCanBeUsed(): void
    {
        $formatter = $this->createMock(ClaimsFormatter::class);
        $config    = Configuration::forUnsecuredSigner();

        self::assertEquals(new BuilderImpl(new JoseEncoder(), $formatter), $config->builder($formatter));
    }
}
