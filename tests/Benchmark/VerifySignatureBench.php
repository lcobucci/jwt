<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use PhpBench\Attributes as Bench;

#[Bench\BeforeMethods('initialize')]
final class VerifySignatureBench extends AlgorithmsBench
{
    private Signer $algorithm;
    private Key $key;
    /** @var non-empty-string */
    private string $signature;

    /** @param array{algorithm: string} $params */
    public function initialize(array $params): void
    {
        $this->algorithm = $this->resolveAlgorithm($params['algorithm']);
        $this->key       = $this->resolveVerificationKey($params['algorithm']);

        $this->signature = $this->algorithm->sign(
            self::PAYLOAD,
            $this->resolveSigningKey($params['algorithm']),
        );
    }

    protected function runBenchmark(): void
    {
        $this->algorithm->verify($this->signature, self::PAYLOAD, $this->key);
    }
}
