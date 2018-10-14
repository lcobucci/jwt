<?php
declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\JWT\Signer\Key;
use PhpBench\Benchmark\Metadata\Annotations\BeforeMethods;
use PhpBench\Benchmark\Metadata\Annotations\Iterations;
use PhpBench\Benchmark\Metadata\Annotations\Revs;

/**
 * @BeforeMethods({"init"})
 * @Iterations(5)
 * @Revs(100)
 */
abstract class SignerBench
{
    private const PAYLOAD = "It\xe2\x80\x99s a dangerous business, Frodo, going out your door. You step onto the road,"
                          . " and if you don't keep your feet, there\xe2\x80\x99s no knowing where you might be swept"
                          . ' off to.';

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
     * @var string
     */
    private $signature;

    final public function init(): void
    {
        $this->signer          = $this->signer();
        $this->signingKey      = $this->signingKey();
        $this->verificationKey = $this->verificationKey();
        $this->signature       = $this->signer->sign(self::PAYLOAD, $this->signingKey);
    }

    final public function benchSignature(): void
    {
        $this->signer->sign(self::PAYLOAD, $this->signingKey);
    }

    final public function benchVerification(): void
    {
        $this->signer->verify($this->signature, self::PAYLOAD, $this->verificationKey);
    }

    abstract protected function signer(): Signer;

    abstract protected function signingKey(): Key;

    abstract protected function verificationKey(): Key;
}
