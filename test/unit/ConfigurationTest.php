<?php

namespace Lcobucci\JWT;

use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Validation\Constraint;
use PHPUnit\Framework\TestCase;
use PHPUnit_Framework_MockObject_MockObject;

/**
 * @coversDefaultClass \Lcobucci\JWT\Configuration
 *
 * @uses \Lcobucci\JWT\Claim\Factory
 * @uses \Lcobucci\JWT\Parser
 * @uses \Lcobucci\JWT\Signer\Key
 * @uses \Lcobucci\JWT\Validation\Validator
 */
final class ConfigurationTest extends TestCase
{
    /** @var Parser&PHPUnit_Framework_MockObject_MockObject */
    private $parser;

    /** @var Signer&PHPUnit_Framework_MockObject_MockObject */
    private $signer;

    /** @var Encoder&PHPUnit_Framework_MockObject_MockObject */
    private $encoder;

    /** @var Decoder&PHPUnit_Framework_MockObject_MockObject */
    private $decoder;

    /** @var Validator&PHPUnit_Framework_MockObject_MockObject */
    private $validator;

    /** @var Constraint&PHPUnit_Framework_MockObject_MockObject */
    private $validationConstraints;

    /** @before */
    public function createDependencies()
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
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys()
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
     * @covers ::__construct
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys()
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
     * @covers ::__construct
     * @covers ::signer
     * @covers ::signingKey
     * @covers ::verificationKey
     *
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function forUnsecuredSignerShouldConfigureSignerAndBothKeys()
    {
        $key    = InMemory::plainText('');
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
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function builderShouldCreateABuilderWithDefaultEncoder()
    {
        $config  = Configuration::forUnsecuredSigner();
        $builder = $config->builder();

        self::assertInstanceOf(Builder::class, $builder);
        self::assertNotEquals(new Builder($this->encoder), $builder);
        self::assertEquals(new Builder(new Encoder()), $builder);
    }

    /**
     * @test
     *
     * @covers ::builder
     * @covers ::__construct
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function builderShouldCreateABuilderWithCustomizedEncoder()
    {
        $config  = Configuration::forUnsecuredSigner($this->encoder);
        $builder = $config->builder();

        self::assertInstanceOf(Builder::class, $builder);
        self::assertEquals(new Builder($this->encoder), $builder);
    }

    /**
     * @test
     *
     * @covers ::builder
     * @covers ::setBuilderFactory
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function builderShouldUseBuilderFactoryWhenThatIsConfigured()
    {
        $builder = $this->createMock(Builder::class);

        $config = Configuration::forUnsecuredSigner();
        $config->setBuilderFactory(
            static function () use ($builder) {
                return $builder;
            }
        );
        self::assertSame($builder, $config->builder());
    }

    /**
     * @test
     *
     * @covers ::parser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function parserShouldReturnAParserWithDefaultDecoder()
    {
        $config = Configuration::forUnsecuredSigner();
        $parser = $config->parser();

        self::assertNotEquals(new Parser($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::parser
     * @covers ::__construct
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function parserShouldReturnAParserWithCustomizedDecoder()
    {
        $config = Configuration::forUnsecuredSigner(null, $this->decoder);
        $parser = $config->parser();

        self::assertEquals(new Parser($this->decoder), $parser);
    }

    /**
     * @test
     *
     * @covers ::parser
     * @covers ::setParser
     *
     * @uses \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function parserShouldNotCreateAnInstanceIfItWasConfigured()
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
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function validatorShouldReturnTheDefaultWhenItWasNotConfigured()
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
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function validatorShouldReturnTheConfiguredValidator()
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
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function validationConstraintsShouldReturnAnEmptyArrayWhenItWasNotConfigured()
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
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key\InMemory
     */
    public function validationConstraintsShouldReturnTheConfiguredValidator()
    {
        $config = Configuration::forUnsecuredSigner();
        $config->setValidationConstraints($this->validationConstraints);

        self::assertSame([$this->validationConstraints], $config->validationConstraints());
    }
}
