<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Closure;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Validation\Constraint;
use NoDiscard;

/**
 * Configuration container for the JWT Builder and Parser
 *
 * Serves like a small DI container to simplify the creation and usage
 * of the objects.
 */
final readonly class Configuration
{
    private Parser $parser;
    private Validator $validator;

    /** @var Closure(ClaimsFormatter $claimFormatter): Builder */
    private Closure $builderFactory;

    /** @var Constraint[] */
    private array $validationConstraints;

    /** @param Closure(ClaimsFormatter $claimFormatter): Builder|null $builderFactory */
    private function __construct(
        private Signer $signer,
        private Key $signingKey,
        private Key $verificationKey,
        private Encoder $encoder,
        private Decoder $decoder,
        ?Parser $parser,
        ?Validator $validator,
        ?Closure $builderFactory,
        Constraint ...$validationConstraints,
    ) {
        $this->parser    = $parser ?? new Token\Parser($decoder);
        $this->validator = $validator ?? new Validation\Validator();

        $this->builderFactory = $builderFactory
            ?? static function (ClaimsFormatter $claimFormatter) use ($encoder): Builder {
                return Token\Builder::new($encoder, $claimFormatter);
            };

        $this->validationConstraints = $validationConstraints;
    }

    #[NoDiscard]
    public static function forAsymmetricSigner(
        Signer $signer,
        Key $signingKey,
        Key $verificationKey,
        Encoder $encoder = new JoseEncoder(),
        Decoder $decoder = new JoseEncoder(),
    ): self {
        return new self(
            $signer,
            $signingKey,
            $verificationKey,
            $encoder,
            $decoder,
            null,
            null,
            null,
        );
    }

    #[NoDiscard]
    public static function forSymmetricSigner(
        Signer $signer,
        Key $key,
        Encoder $encoder = new JoseEncoder(),
        Decoder $decoder = new JoseEncoder(),
    ): self {
        return new self(
            $signer,
            $key,
            $key,
            $encoder,
            $decoder,
            null,
            null,
            null,
        );
    }

    /** @param callable(ClaimsFormatter): Builder $builderFactory */
    #[NoDiscard]
    public function withBuilderFactory(callable $builderFactory): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->parser,
            $this->validator,
            $builderFactory(...),
            ...$this->validationConstraints,
        );
    }

    public function builder(?ClaimsFormatter $claimFormatter = null): Builder
    {
        return ($this->builderFactory)($claimFormatter ?? ChainedFormatter::default());
    }

    public function parser(): Parser
    {
        return $this->parser;
    }

    #[NoDiscard]
    public function withParser(Parser $parser): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $parser,
            $this->validator,
            $this->builderFactory,
            ...$this->validationConstraints,
        );
    }

    public function signer(): Signer
    {
        return $this->signer;
    }

    public function signingKey(): Key
    {
        return $this->signingKey;
    }

    public function verificationKey(): Key
    {
        return $this->verificationKey;
    }

    public function validator(): Validator
    {
        return $this->validator;
    }

    #[NoDiscard]
    public function withValidator(Validator $validator): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->parser,
            $validator,
            $this->builderFactory,
            ...$this->validationConstraints,
        );
    }

    /** @return Constraint[] */
    public function validationConstraints(): array
    {
        return $this->validationConstraints;
    }

    #[NoDiscard]
    public function withValidationConstraints(Constraint ...$validationConstraints): self
    {
        return new self(
            $this->signer,
            $this->signingKey,
            $this->verificationKey,
            $this->encoder,
            $this->decoder,
            $this->parser,
            $this->validator,
            $this->builderFactory,
            ...$validationConstraints,
        );
    }
}
