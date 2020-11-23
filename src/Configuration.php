<?php

namespace Lcobucci\JWT;

use Closure;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
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
    /** @var Parser */
    private $parser;

    /** @var Signer */
    private $signer;

    /** @var Key */
    private $signingKey;

    /** @var Key */
    private $verificationKey;

    /** @var Validator */
    private $validator;

    /** @var Closure(): Builder */
    private $builderFactory;

    /** @var Constraint[] */
    private $validationConstraints = [];

    private function __construct(
        Signer $signer,
        Key $signingKey,
        Key $verificationKey,
        Encoder $encoder = null,
        Decoder $decoder = null
    ) {
        $this->signer          = $signer;
        $this->signingKey      = $signingKey;
        $this->verificationKey = $verificationKey;
        $this->parser          = new Parser($decoder ?: new Decoder());
        $this->validator       = new Validation\Validator();

        $this->builderFactory = static function () use ($encoder) {
            return new Builder($encoder ?: new Encoder());
        };
    }

    /** @return self */
    public static function forAsymmetricSigner(
        Signer $signer,
        Key $signingKey,
        Key $verificationKey,
        Encoder $encoder = null,
        Decoder $decoder = null
    ) {
        return new self(
            $signer,
            $signingKey,
            $verificationKey,
            $encoder,
            $decoder
        );
    }

    /** @return self */
    public static function forSymmetricSigner(
        Signer $signer,
        Key $key,
        Encoder $encoder = null,
        Decoder $decoder = null
    ) {
        return new self(
            $signer,
            $key,
            $key,
            $encoder,
            $decoder
        );
    }

    /** @return self */
    public static function forUnsecuredSigner(
        Encoder $encoder = null,
        Decoder $decoder = null
    ) {
        $key = InMemory::plainText('');

        return new self(
            new None(),
            $key,
            $key,
            $encoder,
            $decoder
        );
    }

    /** @param callable(): Builder $builderFactory */
    public function setBuilderFactory(callable $builderFactory)
    {
        if (! $builderFactory instanceof Closure) {
            $builderFactory = static function() use ($builderFactory) {
                return $builderFactory();
            };
        }
        $this->builderFactory = $builderFactory;
    }

    /** @return Builder */
    public function builder()
    {
        $factory = $this->builderFactory;

        return $factory();
    }

    /** @return Parser */
    public function parser()
    {
        return $this->parser;
    }

    public function setParser(Parser $parser)
    {
        $this->parser = $parser;
    }

    /** @return Signer */
    public function signer()
    {
        return $this->signer;
    }

    /** @return Key */
    public function signingKey()
    {
        return $this->signingKey;
    }

    /** @return Key */
    public function verificationKey()
    {
        return $this->verificationKey;
    }

    /** @return Validator */
    public function validator()
    {
        return $this->validator;
    }

    public function setValidator(Validator $validator)
    {
        $this->validator = $validator;
    }

    /** @return Constraint[] */
    public function validationConstraints()
    {
        return $this->validationConstraints;
    }

    public function setValidationConstraints(Constraint ...$validationConstraints)
    {
        $this->validationConstraints = $validationConstraints;
    }
}
