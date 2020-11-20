<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Token\Builder as BuilderImpl;
use Lcobucci\JWT\Token\Parser as ParserImpl;
use Lcobucci\JWT\Validation\Constraint;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \Lcobucci\JWT\Configuration
 *
 * @uses \Lcobucci\JWT\Encoding\ChainedFormatter
 * @uses \Lcobucci\JWT\Encoding\MicrosecondBasedDateConversion
 * @uses \Lcobucci\JWT\Encoding\UnifyAudience
 * @uses \Lcobucci\JWT\Token\Parser
 * @uses \Lcobucci\JWT\Validation\Validator
 */
final class ConfigurationTest extends TestCase
{
    /** @var Parser&MockObject */
    private Parser $parser;

    /** @var Signer&MockObject */
    private Signer $signer;

    /** @var Encoder&MockObject */
    private Encoder $encoder;

    /** @var Decoder&MockObject */
    private Decoder $decoder;

    /** @var Validator&MockObject */
    private Validator $validator;

    /** @var Constraint&MockObject */
    private Constraint $validationConstraints;

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
     * @covers ::__construct
     * @covers ::getSigner
     * @covers ::getSigningKey
     * @covers ::getVerificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $signingKey      = InMemory::plainText('private');
        $verificationKey = InMemory::plainText('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertSame($this->signer, $config->getSigner());
        self::assertSame($signingKey, $config->getSigningKey());
        self::assertSame($verificationKey, $config->getVerificationKey());
    }

    /**
     * @test
     *
     * @covers ::forSymmetricSigner
     * @covers ::__construct
     * @covers ::getSigner
     * @covers ::getSigningKey
     * @covers ::getVerificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = InMemory::plainText('private');
        $config = Configuration::forSymmetricSigner($this->signer, $key);

        self::assertSame($this->signer, $config->getSigner());
        self::assertSame($key, $config->getSigningKey());
        self::assertSame($key, $config->getVerificationKey());
    }

    /**
     * @test
     *
     * @covers ::forUnsecuredSigner
     * @covers ::__construct
     * @covers ::getSigner
     * @covers ::getSigningKey
     * @covers ::getVerificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forUnsecuredSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = InMemory::plainText('');
        $config = Configuration::forUnsecuredSigner();

        self::assertInstanceOf(None::class, $config->getSigner());
        self::assertEquals($key, $config->getSigningKey());
        self::assertEquals($key, $config->getVerificationKey());
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function createBuilderShouldCreateABuilderWithDefaultEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forUnsecuredSigner();
        $builder = $config->createBuilder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertNotEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
        self::assertEquals(new BuilderImpl(new JoseEncoder(), ChainedFormatter::default()), $builder);
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     * @covers ::__construct
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function createBuilderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forUnsecuredSigner($this->encoder);
        $builder = $config->createBuilder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     * @covers ::setBuilderFactory
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function createBuilderShouldUseBuilderFactoryWhenThatIsConfigured(): void
    {
        $builder = $this->createMock(Builder::class);

        $config = Configuration::forUnsecuredSigner();
        $config->setBuilderFactory(
            static function () use ($builder): Builder {
                return $builder;
            }
        );
        self::assertSame($builder, $config->createBuilder());
    }

    /**
     * @test
     *
     * @covers ::getParser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getParserShouldReturnAParserWithDefaultDecoder(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $parser = $config->getParser();

        self::assertNotEquals(new ParserImpl($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::getParser
     * @covers ::__construct
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getParserShouldReturnAParserWithCustomizedDecoder(): void
    {
        $config = Configuration::forUnsecuredSigner(null, $this->decoder);
        $parser = $config->getParser();

        self::assertEquals(new ParserImpl($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::getParser
     * @covers ::setParser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getParserShouldNotCreateAnInstanceIfItWasConfigured(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setParser($this->parser);

        self::assertSame($this->parser, $config->getParser());
    }

    /**
     * @test
     *
     * @covers ::getValidator
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getValidatorShouldReturnTheDefaultWhenItWasNotConfigured(): void
    {
        $config    = Configuration::forUnsecuredSigner();
        $validator = $config->getValidator();

        self::assertNotSame($this->validator, $validator);
    }

    /**
     * @test
     *
     * @covers ::getValidator
     * @covers ::setValidator
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getValidatorShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidator($this->validator);

        self::assertSame($this->validator, $config->getValidator());
    }

    /**
     * @test
     *
     * @covers ::getValidationConstraints
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getValidationConstraintsShouldReturnAnEmptyArrayWhenItWasNotConfigured(): void
    {
        $config = Configuration::forUnsecuredSigner();

        self::assertSame([], $config->getValidationConstraints());
    }

    /**
     * @test
     *
     * @covers ::getValidationConstraints
     * @covers ::setValidationConstraints
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function getValidationConstraintsShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints($this->validationConstraints);

        self::assertSame([$this->validationConstraints], $config->getValidationConstraints());
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function customClaimFormatterCanBeUsed(): void
    {
        $formatter = $this->createMock(ClaimsFormatter::class);
        $config    = Configuration::forUnsecuredSigner();

        self::assertEquals(new BuilderImpl(new JoseEncoder(), $formatter), $config->createBuilder($formatter));
    }
}
