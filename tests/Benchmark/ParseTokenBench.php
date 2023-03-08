<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Validation\Constraint;
use PhpBench\Attributes as Bench;

#[Bench\BeforeMethods('initialize')]
final class ParseTokenBench extends AlgorithmsBench
{
    private Signer $algorithm;
    private Key $key;
    /** @var non-empty-string */
    private string $jwt;

    /** @param array{algorithm: string} $params */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key       = $this->resolveVerificationKey($params['algorithm']);

        $this->jwt = (new JwtFacade())->issue(
            $this->algorithm,
            $this->resolveSigningKey($params['algorithm']),
            static fn (Builder $builder): Builder => $builder
                ->identifiedBy('token-1')
                ->issuedBy('lcobucci.jwt.benchmarks')
                ->relatedTo('user-1')
                ->permittedFor('lcobucci.jwt'),
        )->toString();
    }

    protected function runBenchmark(): void
    {
        (new JwtFacade())->parse(
            $this->jwt,
            new Constraint\SignedWith($this->algorithm, $this->key),
            new Constraint\StrictValidAt(SystemClock::fromSystemTimezone()),
            new Constraint\IssuedBy('lcobucci.jwt.benchmarks'),
            new Constraint\RelatedTo('user-1'),
            new Constraint\PermittedFor('lcobucci.jwt'),
            new Constraint\IdentifiedBy('token-1'),
        );
    }
}
