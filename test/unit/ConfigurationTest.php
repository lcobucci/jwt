<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Token\Builder as BuilderImpl;
use Lcobucci\JWT\Token\Parser as ParserImpl;
use Lcobucci\JWT\Validation\Constraint;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/** @coversDefaultClass \Lcobucci\JWT\Configuration */
final class ConfigurationTest extends TestCase
{
    /** @var Parser&MockObject */
    private Parser $parser;

    /** @var Signer&MockObject */
    private Signer $signer;

    /** @var Parsing\Encoder&MockObject */
    private Parsing\Encoder $encoder;

    /** @var Parsing\Decoder&MockObject */
    private Parsing\Decoder $decoder;

    /** @var Validator&MockObject */
    private Validator $validator;

    /** @var Constraint&MockObject */
    private Constraint $validationConstraints;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->signer                = $this->createMock(Signer::class);
        $this->encoder               = $this->createMock(Parsing\Encoder::class);
        $this->decoder               = $this->createMock(Parsing\Decoder::class);
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
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $signingKey      = new Key('private');
        $verificationKey = new Key('public');

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
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = new Key('private');
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
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forUnsecuredSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = new Key('');
        $config = Configuration::forUnsecuredSigner();

        self::assertInstanceOf(None::class, $config->getSigner());
        self::assertEquals($key, $config->getSigningKey());
        self::assertEquals($key, $config->getVerificationKey());
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     * @covers ::getBuilderFactory
     * @covers ::getEncoder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Token\Parser
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function createBuilderShouldCreateABuilderWithDefaultEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forUnsecuredSigner();
        $builder = $config->createBuilder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertNotEquals(new BuilderImpl($this->encoder), $builder);
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     * @covers ::getBuilderFactory
     * @covers ::setEncoder
     * @covers ::getEncoder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function createBuilderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setEncoder($this->encoder);

        $builder = $config->createBuilder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertEquals(new BuilderImpl($this->encoder), $builder);
    }

    /**
     * @test
     *
     * @covers ::createBuilder
     * @covers ::getBuilderFactory
     * @covers ::setBuilderFactory
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Builder
     * @uses \Lcobucci\JWT\Token\Parser
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @covers ::getDecoder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Parser
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @covers ::setDecoder
     * @covers ::getDecoder
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Token\Parser
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function getParserShouldReturnAParserWithCustomizedDecoder(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setDecoder($this->decoder);

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
     * @uses \Lcobucci\JWT\Token\Parser
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @uses \Lcobucci\JWT\Signer\Key
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
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function getValidationConstraintsShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints($this->validationConstraints);

        self::assertSame([$this->validationConstraints], $config->getValidationConstraints());
    }
}
