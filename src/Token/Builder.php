<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

use DateTimeImmutable;
use InvalidArgumentException;
use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Builder as BuilderInterface;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use function array_diff;
use function array_intersect;
use function array_keys;
use function array_merge;
use function count;
use function current;
use function in_array;

final class Builder implements BuilderInterface
{
    /**
     * @var array<string, mixed>
     */
    private array $headers = ['typ' => 'JWT', 'alg' => null];

    /**
     * @var array<string, mixed>
     */
    private array $claims = [];

    private Parsing\Encoder $encoder;

    public function __construct(Parsing\Encoder $encoder)
    {
        $this->encoder = $encoder;
    }

    public function permittedFor(string ...$audiences): BuilderInterface
    {
        $configured = $this->claims[RegisteredClaims::AUDIENCE] ?? [];
        $toAppend   = array_diff($audiences, $configured);

        return $this->setClaim(RegisteredClaims::AUDIENCE, array_merge($configured, $toAppend));
    }

    public function expiresAt(DateTimeImmutable $expiration): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::EXPIRATION_TIME, $expiration);
    }

    public function identifiedBy(string $id): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ID, $id);
    }

    public function issuedAt(DateTimeImmutable $issuedAt): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ISSUED_AT, $issuedAt);
    }

    public function issuedBy(string $issuer): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::ISSUER, $issuer);
    }

    public function canOnlyBeUsedAfter(DateTimeImmutable $notBefore): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::NOT_BEFORE, $notBefore);
    }

    public function relatedTo(string $subject): BuilderInterface
    {
        return $this->setClaim(RegisteredClaims::SUBJECT, $subject);
    }

    /**
     * {@inheritdoc}
     */
    public function withHeader(string $name, $value): BuilderInterface
    {
        $this->headers[$name] = $value;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function withClaim(string $name, $value): BuilderInterface
    {
        if (in_array($name, RegisteredClaims::ALL, true)) {
            throw new InvalidArgumentException('You should use the correct methods to set registered claims');
        }

        return $this->setClaim($name, $value);
    }

    /**
     * @param mixed $value
     */
    private function setClaim(string $name, $value): BuilderInterface
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * @param array<string, mixed> $items
     */
    private function encode(array $items): string
    {
        return $this->encoder->base64UrlEncode(
            $this->encoder->jsonEncode($items)
        );
    }

    public function getToken(Signer $signer, Key $key): Plain
    {
        $headers        = $this->headers;
        $headers['alg'] = $signer->getAlgorithmId();

        $encodedHeaders = $this->encode($headers);
        $encodedClaims  = $this->encode($this->formatClaims($this->claims));

        $signature        = $signer->sign($encodedHeaders . '.' . $encodedClaims, $key);
        $encodedSignature = $this->encoder->base64UrlEncode($signature);

        return new Plain(
            new DataSet($headers, $encodedHeaders),
            new DataSet($this->claims, $encodedClaims),
            new Signature($signature, $encodedSignature)
        );
    }

    /**
     * @param mixed[] $claims
     *
     * @return mixed[]
     */
    private function formatClaims(array $claims): array
    {
        if (count($claims[RegisteredClaims::AUDIENCE]) === 1) {
            $claims[RegisteredClaims::AUDIENCE] = current($claims[RegisteredClaims::AUDIENCE]);
        }

        foreach (array_intersect(RegisteredClaims::DATE_CLAIMS, array_keys($claims)) as $claim) {
            $claims[$claim] = $this->convertDate($claims[$claim]);
        }

        return $claims;
    }

    /**
     * @return int|string
     */
    private function convertDate(DateTimeImmutable $date)
    {
        $seconds      = $date->format('U');
        $microseconds = $date->format('u');

        if ((int) $microseconds === 0) {
            return (int) $seconds;
        }

        return $seconds . '.' . $microseconds;
    }
}
