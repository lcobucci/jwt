<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\CannotEncodeContent;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\UnencryptedToken;
use NoDiscard;

use function array_diff;
use function array_merge;
use function in_array;

/** @immutable */
final readonly class Builder implements BuilderInterface
{
    /**
     * @param array<non-empty-string, mixed> $headers
     * @param array<non-empty-string, mixed> $claims
     */
    private function __construct(
        private Encoder $encoder,
        private ClaimsFormatter $claimFormatter,
        private array $headers = ['typ' => 'JWT', 'alg' => null],
        private array $claims = [],
    ) {
    }

    #[NoDiscard]
    public static function new(Encoder $encoder, ClaimsFormatter $claimFormatter): self
    {
        return new self($encoder, $claimFormatter);
    }

    public function permittedFor(string ...$audiences): BuilderInterface
    {
        $configured = $this->claims[RegisteredClaims::AUDIENCE] ?? [];
        $toAppend   = array_diff($audiences, $configured);

        return $this->newWithClaim(RegisteredClaims::AUDIENCE, array_merge($configured, $toAppend));
    }

    public function expiresAt(DateTimeImmutable $expiration): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::EXPIRATION_TIME, $expiration);
    }

    public function identifiedBy(string $id): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ID, $id);
    }

    public function issuedAt(DateTimeImmutable $issuedAt): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ISSUED_AT, $issuedAt);
    }

    public function issuedBy(string $issuer): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::ISSUER, $issuer);
    }

    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::NOT_BEFORE, $notBefore);
    }

    public function relatedTo(string $subject): BuilderInterface
    {
        return $this->newWithClaim(RegisteredClaims::SUBJECT, $subject);
    }

    public function withHeader(string $name, mixed $value): BuilderInterface
    {
        $headers        = $this->headers;
        $headers[$name] = $value;

        return new self(
            $this->encoder,
            $this->claimFormatter,
            $headers,
            $this->claims,
        );
    }

    public function withClaim(string $name, mixed $value): BuilderInterface
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            throw RegisteredClaimGiven::forClaim($name);
        }

        return $this->newWithClaim($name, $value);
    }

    /** @param non-empty-string $name */
    private function newWithClaim(string $name, mixed $value): BuilderInterface
    {
        $claims        = $this->claims;
        $claims[$name] = $value;

        return new self(
            $this->encoder,
            $this->claimFormatter,
            $this->headers,
            $claims,
        );
    }

    /**
     * @param array<non-empty-string, mixed> $items
     *
     * @throws CannotEncodeContent When data cannot be converted to JSON.
     */
    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items),
        );
    }

    public function getToken(Signer $signer, Key $key): UnencryptedToken
    {
        $headers        = $this->headers;
        $headers['alg'] = $signer->algorithmId();

        $encodedHeaders = $this->encode($headers);
        $encodedClaims  = $this->encode($this->claimFormatter->formatClaims($this->claims));

        $signature        = $signer->sign($encodedHeaders . '.' . $encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Plain(
            new DataSet($headers, $encodedHeaders),
            new DataSet($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature),
        );
    }
}
