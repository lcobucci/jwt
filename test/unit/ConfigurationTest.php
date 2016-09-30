<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class ConfigurationTest extends \PHPUnit_Framework_TestCase
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
     * @var ClaimFactory|\PHPUnit_Framework_MockObject_MockObject
     */
    private $claimFactory;

    /**
     * @var Parsing\Encoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $encoder;

    /**
     * @var Parsing\Decoder|\PHPUnit_Framework_MockObject_MockObject
     */
    private $decoder;

    /**
     * @before
     */
    public function createDependencies()
    {
        $this->signer = $this->createMock(Signer::class);
        $this->encoder = $this->createMock(Parsing\Encoder::class);
        $this->decoder = $this->createMock(Parsing\Decoder::class);
        $this->claimFactory = new ClaimFactory();
        $this->parser = new Parser($this->decoder, $this->claimFactory);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
     * @covers \Lcobucci\JWT\Configuration::getClaimFactory
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function createBuilderShouldCreateABuilderWithDefaultEncoderAndClaimFactory()
    {
        $config = new Configuration();
        $builder = $config->createBuilder();

        $this->assertInstanceOf(Builder::class, $builder);
        $this->assertAttributeNotSame($this->encoder, 'encoder', $builder);
        $this->assertAttributeNotSame($this->claimFactory, 'claimFactory', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::createBuilder
     * @covers \Lcobucci\JWT\Configuration::setEncoder
     * @covers \Lcobucci\JWT\Configuration::getEncoder
     * @covers \Lcobucci\JWT\Configuration::getClaimFactory
     * @covers \Lcobucci\JWT\Configuration::setClaimFactory
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function createBuilderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory()
    {
        $config = new Configuration();
        $config->setEncoder($this->encoder);
        $config->setClaimFactory($this->claimFactory);

        $builder = $config->createBuilder();

        $this->assertInstanceOf(Builder::class, $builder);
        $this->assertAttributeSame($this->encoder, 'encoder', $builder);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $builder);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::getDecoder
     * @covers \Lcobucci\JWT\Configuration::getClaimFactory
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function getParserShouldReturnAParserWithDefaultDecoderAndClaimFactory()
    {
        $config = new Configuration();
        $parser = $config->getParser();

        $this->assertInstanceOf(Parser::class, $parser);
        $this->assertAttributeNotSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeNotSame($this->claimFactory, 'claimFactory', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setDecoder
     * @covers \Lcobucci\JWT\Configuration::getDecoder
     * @covers \Lcobucci\JWT\Configuration::getClaimFactory
     * @covers \Lcobucci\JWT\Configuration::setClaimFactory
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function getParserShouldReturnAParserWithCustomizedDecoderAndClaimFactory()
    {
        $config = new Configuration();
        $config->setDecoder($this->decoder);
        $config->setClaimFactory($this->claimFactory);

        $parser = $config->getParser();

        $this->assertInstanceOf(Parser::class, $parser);
        $this->assertAttributeSame($this->decoder, 'decoder', $parser);
        $this->assertAttributeSame($this->claimFactory, 'claimFactory', $parser);
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getParser
     * @covers \Lcobucci\JWT\Configuration::setParser
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function getParserShouldNotCreateAnInstanceIfItWasConfigured()
    {
        $config = new Configuration();
        $config->setParser($this->parser);

        $this->assertSame($this->parser, $config->getParser());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getSigner
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     * @uses \Lcobucci\JWT\Signer\Hmac\Sha256
     */
    public function getSignerShouldReturnTheDefaultWhenItWasNotConfigured()
    {
        $config = new Configuration();

        $this->assertInstanceOf(Sha256::class, $config->getSigner());
    }

    /**
     * @test
     *
     * @covers \Lcobucci\JWT\Configuration::getSigner
     * @covers \Lcobucci\JWT\Configuration::setSigner
     *
     * @uses \Lcobucci\JWT\Builder
     * @uses \Lcobucci\JWT\Claim\Factory
     * @uses \Lcobucci\JWT\Parser
     */
    public function getSignerShouldReturnTheConfiguredSigner()
    {
        $config = new Configuration();
        $config->setSigner($this->signer);

        $this->assertSame($this->signer, $config->getSigner());
    }
}
