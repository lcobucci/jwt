<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Tests\Benchmark;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use PhpBench\Attributes as Bench;
use RuntimeException;

#[Bench\Iterations(5)]
#[Bench\Revs(100)]
#[Bench\Warmup(3)]
abstract class AlgorithmsBench
{
    private const SUPPORTED_ALGORITHMS = [
        'hmac' => ['HS256', 'HS384', 'HS512'],
        'rsa' => ['RS256', 'RS384', 'RS512'],
        'ecdsa' => ['ES256', 'ES384', 'ES512'],
        'eddsa' => ['EdDSA'],
        'blake2b' => ['BLAKE2B'],
    ];

    protected const PAYLOAD = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road"
        . ", and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept"
        . ' off to.';

    #[Bench\Subject]
    #[Bench\ParamProviders('hmacAlgorithms')]
    #[Bench\Groups(['hmac', 'symmetric'])]
    public function hmac(): void
    {
        $this->runBenchmark();
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function hmacAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('hmac');
    }

    #[Bench\Subject]
    #[Bench\ParamProviders('rsaAlgorithms')]
    #[Bench\Groups(['rsa', 'asymmetric'])]
    public function rsa(): void
    {
        $this->runBenchmark();
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function rsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('rsa');
    }

    #[Bench\Subject]
    #[Bench\ParamProviders('ecdsaAlgorithms')]
    #[Bench\Groups(['ecdsa', 'asymmetric'])]
    public function ecdsa(): void
    {
        $this->runBenchmark();
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function ecdsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('ecdsa');
    }

    #[Bench\Subject]
    #[Bench\ParamProviders('eddsaAlgorithms')]
    #[Bench\Groups(['eddsa', 'asymmetric'])]
    public function eddsa(): void
    {
        $this->runBenchmark();
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function eddsaAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('eddsa');
    }

    #[Bench\Subject]
    #[Bench\ParamProviders('blake2bAlgorithms')]
    #[Bench\Groups(['blake2b', 'symmetric'])]
    public function blake2b(): void
    {
        $this->runBenchmark();
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function blake2bAlgorithms(): iterable
    {
        yield from $this->iterateAlgorithms('blake2b');
    }

    abstract protected function runBenchmark(): void;

    protected function resolveAlgorithm(string $name): Signer
    {
        return match ($name) {
            'HS256' => new Signer\Hmac\Sha256(),
            'HS384' => new Signer\Hmac\Sha384(),
            'HS512' => new Signer\Hmac\Sha512(),
            'RS256' => new Signer\Rsa\Sha256(),
            'RS384' => new Signer\Rsa\Sha384(),
            'RS512' => new Signer\Rsa\Sha512(),
            'ES256' => new Signer\Ecdsa\Sha256(),
            'ES384' => new Signer\Ecdsa\Sha384(),
            'ES512' => new Signer\Ecdsa\Sha512(),
            'EdDSA' => new Signer\Eddsa(),
            'BLAKE2B' => new Signer\Blake2b(),
            default => throw new RuntimeException('Unknown algorithm'),
        };
    }

    protected function resolveSigningKey(string $name): Key
    {
        return match ($name) {
            'HS256' => InMemory::base64Encoded('n5p7sBK+dvBmSKNlQIFrsuB1cnmnwsxGyWXPgRSZtWY='),
            'HS384' => InMemory::base64Encoded('kNUb8KvJC+fvhPzIuimwWHleES3AAnUjI+UIWZyor5HT33st9KIjfPkgtfu60UL2'),
            'HS512' => InMemory::base64Encoded(
                'OgXKIs+aZCQgXnDfi8mAFnWVo+Xn3JTR7BvT/j1Q1zP9oRx9xGg4jmpq00RsPPDclYi8+jRl664pu4d0zan2ow==',
            ),
            'RS256', 'RS384', 'RS512' => InMemory::file(__DIR__ . '/Rsa/private.key'),
            'ES256' => InMemory::file(__DIR__ . '/Ecdsa/private-256.key'),
            'ES384' => InMemory::file(__DIR__ . '/Ecdsa/private-384.key'),
            'ES512' => InMemory::file(__DIR__ . '/Ecdsa/private-521.key'),
            'EdDSA' => InMemory::base64Encoded(
                'K3NWT0XqaH+4jgi42gQmHnFE+HTPVhFYi3u4DFJ3OpRHRMt/aGRBoKD/Pt5H/iYgGCla7Q04CdjOUpLSrjZhtg==',
            ),
            'BLAKE2B' => InMemory::base64Encoded('b6DNRcX2SFapbICe6lXWYoOZA+JXL/dvkfWiv2hJv3Y='),
            default => throw new RuntimeException('Unknown algorithm'),
        };
    }

    protected function resolveVerificationKey(string $name): Key
    {
        return match ($name) {
            'HS256', 'HS384', 'HS512', 'BLAKE2B' => $this->resolveSigningKey($name),
            'RS256', 'RS384', 'RS512' => InMemory::file(__DIR__ . '/Rsa/public.key'),
            'ES256' => InMemory::file(__DIR__ . '/Ecdsa/public-256.key'),
            'ES384' => InMemory::file(__DIR__ . '/Ecdsa/public-384.key'),
            'ES512' => InMemory::file(__DIR__ . '/Ecdsa/public-521.key'),
            'EdDSA' => InMemory::base64Encoded('R0TLf2hkQaCg/z7eR/4mIBgpWu0NOAnYzlKS0q42YbY='),
            default => throw new RuntimeException('Unknown algorithm'),
        };
    }

    /** @return iterable<string, array{algorithm: string}> */
    private function iterateAlgorithms(string $family): iterable
    {
        foreach (self::SUPPORTED_ALGORITHMS[$family] ?? [] as $algorithm) {
            yield $algorithm => ['algorithm' => $algorithm];
        }
    }
}
