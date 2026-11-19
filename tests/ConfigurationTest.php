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
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

#[PHPUnit\CoversClass(Configuration::class)]
#[PHPUnit\UsesClass(ChainedFormatter::class)]
#[PHPUnit\UsesClass(InMemory::class)]
#[PHPUnit\UsesClass(BuilderImpl::class)]
#[PHPUnit\UsesClass(ParserImpl::class)]
#[PHPUnit\UsesClass(\Lcobucci\JWT\Validation\Validator::class)]
final class ConfigurationTest extends TestCase
{
    private Parser&Stub $parser;
    private Signer&Stub $signer;
    private Encoder&Stub $encoder;
    private Decoder&Stub $decoder;
    private Validator&Stub $validator;
    private Constraint&Stub $validationConstraints;

    #[PHPUnit\Before]
    public function createDependencies(): void
    {
        $this->signer                = self::createStub(Signer::class);
        $this->encoder               = self::createStub(Encoder::class);
        $this->decoder               = self::createStub(Decoder::class);
        $this->parser                = self::createStub(Parser::class);
        $this->validator             = self::createStub(Validator::class);
        $this->validationConstraints = self::createStub(Constraint::class);
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
        self::assertNotEquals(BuilderImpl::new($this->encoder, ChainedFormatter::default()), $builder);
        self::assertEquals(BuilderImpl::new(new JoseEncoder(), ChainedFormatter::default()), $builder);
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
        self::assertEquals(BuilderImpl::new($this->encoder, ChainedFormatter::default()), $builder);
    }

    #[PHPUnit\Test]
    public function builderShouldUseBuilderFactoryWhenThatIsConfigured(): void
    {
        $builder = self::createStub(Builder::class);

        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withBuilderFactory(
            static function () use ($builder): Builder {
                return $builder;
            },
        );
        self::assertNotSame($builder, $config->builder());
        self::assertSame($builder, $newConfig->builder());
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
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withParser($this->parser);

        self::assertNotSame($this->parser, $config->parser());
        self::assertSame($this->parser, $newConfig->parser());
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
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withValidator($this->validator);

        self::assertNotSame($this->validator, $config->validator());
        self::assertSame($this->validator, $newConfig->validator());
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
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );
        $newConfig = $config->withValidationConstraints($this->validationConstraints);

        self::assertNotSame([$this->validationConstraints], $config->validationConstraints());
        self::assertSame([$this->validationConstraints], $newConfig->validationConstraints());
    }

    #[PHPUnit\Test]
    public function customClaimFormatterCanBeUsed(): void
    {
        $formatter = self::createStub(ClaimsFormatter::class);
        $config    = Configuration::forSymmetricSigner(
            new KeyDumpSigner(),
            InMemory::plainText('private'),
        );

        self::assertEquals(BuilderImpl::new(new JoseEncoder(), $formatter), $config->builder($formatter));
    }
}
