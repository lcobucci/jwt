<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

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
    /**
     * @var Parser|null
     */
    private $parser;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Key
     */
    private $signingKey;

    /**
     * @var Key
     */
    private $verificationKey;

    /**
     * @var Parsing\Encoder|null
     */
    private $encoder;

    /**
     * @var Parsing\Decoder|null
     */
    private $decoder;

    /**
     * @var Validator|null
     */
    private $validator;

    /**
     * @var Constraint[]
     */
    private $validationConstraints = [];

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

    private function __construct(
        Signer $signer,
        Key $signingKey,
        Key $verificationKey
    ) {
        $this->signer          = $signer;
        $this->signingKey      = $signingKey;
        $this->verificationKey = $verificationKey;
    }

    public function createBuilder(): Builder
    {
        return new Token\Builder($this->getEncoder());
    }

    public function getParser(): Parser
    {
        if ($this->parser === null) {
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
        if ($this->encoder === null) {
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
        if ($this->decoder === null) {
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
        if ($this->validator === null) {
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
