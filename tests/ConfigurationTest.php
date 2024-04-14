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
use Lcobucci\JWT\Token\Builder as BuilderImpl;
use Lcobucci\JWT\Token\Parser as ParserImpl;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validator;
use PHPUnit\Framework\Attributes as PHPUnit;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\UsesClass(ChainedFormatter::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(BuilderImpl::class)]
#[PHPUnit\UsesClass(ParserImpl::class)]
#[PHPUnit\UsesClass(\Lcobucci\JWT\Validation\Validator::class)]
final class ConfigurationTest extends TestCase
{
    private Parser&MockObject $parser;
    private Signer&MockObject $signer;
    private Encoder&MockObject $encoder;
    private Decoder&MockObject $decoder;
    private Validator&MockObject $validator;
    private Constraint&MockObject $validationConstraints;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->signer                = $this->createMock(Signer::class);
        $this->encoder               = $this->createMock(Encoder::class);
        $this->decoder               = $this->createMock(Decoder::class);
        $this->parser                = $this->createMock(Parser::class);
        $this->validator             = $this->createMock(Validator::class);
        $this->validationConstraints = $this->createMock(Constraint::class);
    }

    #[PHPUnit\Test]
    public function forAsymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $signingKey      = InMemory::plainText('private');
        $verificationKey = InMemory::plainText('public');

        $config = Configuration::forAsymmetricSigner($this->signer, $signingKey, $verificationKey);

        self::assertSame($this->signer, $config->signer());
        self::assertSame($signingKey, $config->signingKey());
        self::assertSame($verificationKey, $config->verificationKey());
    }

    #[PHPUnit\Test]
    public function forSymmetricSignerShouldConfigureSignerAndBothKeys(): void
    {
        $key    = InMemory::plainText('private');
        $config = Configuration::forSymmetricSigner($this->signer, $key);

        self::assertSame($this->signer, $config->signer());
        self::assertSame($key, $config->signingKey());
        self::assertSame($key, $config->verificationKey());
    }

    #[PHPUnit\Test]
    public function builderShouldCreateABuilderWithDefaultEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $builder = $config->builder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertNotEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
        self::assertEquals(new BuilderImpl(new JoseEncoder(), ChainedFormatter::default()), $builder);
    }

    #[PHPUnit\Test]
    public function builderShouldCreateABuilderWithCustomizedEncoderAndClaimFactory(): void
    {
        $config  = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
            $this->encoder,
        );
        $builder = $config->builder();

        self::assertInstanceOf(BuilderImpl::class, $builder);
        self::assertEquals(new BuilderImpl($this->encoder, ChainedFormatter::default()), $builder);
    }

    #[PHPUnit\Test]
    public function builderShouldUseBuilderFactoryWhenThatIsConfigured(): void
    {
        $builder = $this->createMock(Builder::class);

        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $config->setBuilderFactory(
            static function () use ($builder): Builder {
                return $builder;
            },
        );
        self::assertSame($builder, $config->builder());
    }

    #[PHPUnit\Test]
    public function parserShouldReturnAParserWithDefaultDecoder(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $parser = $config->parser();

        self::assertNotEquals(new ParserImpl($this->decoder), $parser);
    }

    #[PHPUnit\Test]
    public function parserShouldReturnAParserWithCustomizedDecoder(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
            decoder: $this->decoder,
        );
        $parser = $config->parser();

        self::assertEquals(new ParserImpl($this->decoder), $parser);
    }

    #[PHPUnit\Test]
    public function parserShouldNotCreateAnInstanceIfItWasConfigured(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $config->setParser($this->parser);

        self::assertSame($this->parser, $config->parser());
    }

    #[PHPUnit\Test]
    public function validatorShouldReturnTheDefaultWhenItWasNotConfigured(): void
    {
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $validator = $config->validator();

        self::assertNotSame($this->validator, $validator);
    }

    #[PHPUnit\Test]
    public function validatorShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $config->setValidator($this->validator);

        self::assertSame($this->validator, $config->validator());
    }

    #[PHPUnit\Test]
    public function validationConstraintsShouldReturnAnEmptyArrayWhenItWasNotConfigured(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        self::assertSame([], $config->validationConstraints());
    }

    #[PHPUnit\Test]
    public function validationConstraintsShouldReturnTheConfiguredValidator(): void
    {
        $config = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $config->setValidationConstraints($this->validationConstraints);

        self::assertSame([$this->validationConstraints], $config->validationConstraints());
    }

    #[PHPUnit\Test]
    public function customClaimFormatterCanBeUsed(): void
    {
        $formatter = $this->createMock(ClaimsFormatter::class);
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        self::assertEquals(new BuilderImpl(new JoseEncoder(), $formatter), $config->builder($formatter));
    }
}
