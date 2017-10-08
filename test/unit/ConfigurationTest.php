<?php

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Token\Builder as BuilderImpl;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class ConfigurationTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @var Parser|\PHPUnit_Framework_MockObject_MockObject
     */
    private $parser;

    /**
     * @var Signer|\PHPUnit_Framework_MockObject_MockObject
     */
    private $signer;

    /**
     * @var Parsing\Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $encoder;

    /**
     * @var Parsing\Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $decoder;

    /**
     * @var Validator|\PHPUnit_Framework_MockObject_MockObject
     */
    private $validator;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->signer    = $this->createMock(Signer::class);
        $this->encoder   = $this->createMock(Parsing\Encoder::class);
        $this->decoder   = $this->createMock(Parsing\Decoder::class);
        $this->parser    = $this->createMock(Parser::class);
        $this->validator = $this->createMock(Validator::class);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::forAsymmetricSigner
     * @covers \Lcobucci\JWT\Configuration::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $signingKey      = new Key('private');
        $verificationKey = new Key('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertAttributeSame($this->signer, 'signer', $config);
        self::assertAttributeSame($signingKey, 'signingKey', $config);
        self::assertAttributeSame($verificationKey, 'verificationKey', $config);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::forSymmetricSigner
     * @covers \Lcobucci\JWT\Configuration::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = new Key('private');
        $config = Configuration::forSymmetricSigner($this->signer, $key);

        self::assertAttributeSame($this->signer, 'signer', $config);
        self::assertAttributeSame($key, 'signingKey', $config);
        self::assertAttributeSame($key, 'verificationKey', $config);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::forUnsecuredSigner
     * @covers \Lcobucci\JWT\Configuration::__construct
     *
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function forUnsecuredSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = new Key('');
        $config = Configuration::forUnsecuredSigner();

        self::assertAttributeInstanceOf(None::class, 'signer', $config);
        self::assertAttributeEquals($key, 'signingKey', $config);
        self::assertAttributeEquals($key, 'verificationKey', $config);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
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
        self::assertAttributeNotSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::setEncoder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
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
        self::assertAttributeSame($this->encoder, 'encoder', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::getDecoder
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

        self::assertInstanceOf(Parser::class, $parser);
        self::assertAttributeNotSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setDecoder
     * @covers \Lcobucci\JWT\Configuration::getDecoder
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

        self::assertInstanceOf(Parser::class, $parser);
        self::assertAttributeSame($this->decoder, 'decoder', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setParser
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
     * @covers \Lcobucci\JWT\Configuration::getSigner
     *
     * @uses \Lcobucci\JWT\Configuration::forSymmetricSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\None
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function getSignerShouldReturnTheConfiguredSigner(): void
    {
        $config = Configuration::forSymmetricSigner($this->signer, new Key(''));

        self::assertSame($this->signer, $config->getSigner());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getSigningKey()
     *
     * @uses \Lcobucci\JWT\Configuration::forAsymmetricSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function getSigningKeyShouldReturnTheConfiguredKey(): void
    {
        $signingKey      = new Key('private');
        $verificationKey = new Key('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertSame($signingKey, $config->getSigningKey());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getVerificationKey()
     *
     * @uses \Lcobucci\JWT\Configuration::forAsymmetricSigner
     * @uses \Lcobucci\JWT\Configuration::__construct
     * @uses \Lcobucci\JWT\Signer\Key
     */
    public function getVerificationKeyShouldReturnTheConfiguredKey(): void
    {
        $signingKey      = new Key('private');
        $verificationKey = new Key('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertSame($verificationKey, $config->getVerificationKey());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getValidator
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
     * @covers \Lcobucci\JWT\Configuration::getValidator
     * @covers \Lcobucci\JWT\Configuration::setValidator
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
}
