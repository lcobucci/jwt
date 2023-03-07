<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use PhpBench\Attributes as Bench;

#[Bench\BeforeMethods('initialize')]
final class IssueTokenBench extends AlgorithmsBench
{
    private Signer $algorithm;
    private Key $key;

    /** @param array{algorithm: string} $params */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key       = $this->resolveSigningKey($params['algorithm']);
    }

    protected function runBenchmark(): void
    {
        (new JwtFacade())->issue(
            $this->algorithm,
            $this->key,
            static fn (Builder $builder): Builder => $builder
                ->identifiedBy('token-1')
                ->issuedBy('lcobucci.jwt.benchmarks')
                ->relatedTo('user-1')
                ->permittedFor('lcobucci.jwt'),
        );
    }
}
