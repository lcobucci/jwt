<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Closure;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\None;
use Lcobucci\JWT\Validation\Constraint;

/**
 * Configuration container for the JWT Builder and Parser
 *
 * Serves like a small DI container to simplify the creation and usage
 * of the objects.
 */
final class Configuration
{
    private Parser $parser;
    private Signer $signer;
    private Key $signingKey;
    private Key $verificationKey;
    private Parsing\Encoder $encoder;
    private Parsing\Decoder $decoder;
    private Validator $validator;
    private Closure $builderFactory;

    /**
     * @var Constraint[]
     */
    private array $validationConstraints = [];

    public static function forAsymmetricSigner(
        Signer $signer,
        Key $signingKey,
        Key $verificationKey
    ): self {
        return new self($signer, $signingKey, $verificationKey);
    }

    public static function forSymmetricSigner(Signer $signer, Key $key): self
    {
        return new self($signer, $key, $key);
    }

    public static function forUnsecuredSigner(): self
    {
        $key = new Key('');

        return new self(new None(), $key, $key);
    }

    private function __construct(Signer $signer, Key $signingKey, Key $verificationKey)
    {
        $this->signer          = $signer;
        $this->signingKey      = $signingKey;
        $this->verificationKey = $verificationKey;
    }

    private function getBuilderFactory(): Closure
    {
        if (! isset($this->builderFactory)) {
            $this->builderFactory = function (): Builder {
                return new Token\Builder($this->getEncoder());
            };
        }

        return $this->builderFactory;
    }

    public function setBuilderFactory(callable $builderFactory): void
    {
        $this->builderFactory = Closure::fromCallable($builderFactory);
    }

    public function createBuilder(): Builder
    {
        return ($this->getBuilderFactory())();
    }

    public function getParser(): Parser
    {
        if (! isset($this->parser)) {
            $this->parser = new Token\Parser($this->getDecoder());
        }

        return $this->parser;
    }

    public function setParser(Parser $parser): void
    {
        $this->parser = $parser;
    }

    public function getSigner(): Signer
    {
        return $this->signer;
    }

    public function getSigningKey(): Key
    {
        return $this->signingKey;
    }

    public function getVerificationKey(): Key
    {
        return $this->verificationKey;
    }

    private function getEncoder(): Parsing\Encoder
    {
        if (! isset($this->encoder)) {
            $this->encoder = new Parsing\Parser();
        }

        return $this->encoder;
    }

    public function setEncoder(Parsing\Encoder $encoder): void
    {
        $this->encoder = $encoder;
    }

    private function getDecoder(): Parsing\Decoder
    {
        if (! isset($this->decoder)) {
            $this->decoder = new Parsing\Parser();
        }

        return $this->decoder;
    }

    public function setDecoder(Parsing\Decoder $decoder): void
    {
        $this->decoder = $decoder;
    }

    public function getValidator(): Validator
    {
        if (! isset($this->validator)) {
            $this->validator = new Validation\Validator();
        }

        return $this->validator;
    }

    public function setValidator(Validator $validator): void
    {
        $this->validator = $validator;
    }

    /**
     * @return Constraint[]
     */
    public function getValidationConstraints(): array
    {
        return $this->validationConstraints;
    }

    public function setValidationConstraints(Constraint ...$validationConstraints): void
    {
        $this->validationConstraints = $validationConstraints;
    }
}
