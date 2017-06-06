<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Lcobucci\JWT\Signer;

/**
 * Class that holds a registry of signers
 *
 * @author Woody Gilk <@shadowhand>
 * @since 3.0.6
 */
class Factory
{
    /**
     * The currently registered signers
     *
     * @var array
     */
    private $registry = [];

    /**
     * Prefixes used for namespaces
     *
     * @var array
     */
    private $prefixes = [
        'ES' => 'Ecdsa',
        'HS' => 'Hmac',
        'RS' => 'Rsa',
    ];

    /**
     * Initializes the factory, registering custom signers
     *
     * @param array $registry
     * @param array $prefixes
     */
    public function __construct(array $registry = [], array $prefixes = [])
    {
        foreach ($registry as $signer) {
            $this->register($signer);
        }

        $this->prefixes = array_replace($this->prefixes, $prefixes);
    }

    /**
     * Register a signer
     *
     * @param Signer $signer
     *
     * @return self
     */
    public function register(Signer $signer)
    {
        $this->registry[$signer->getAlgorithmId()] = $signer;

        return $this;
    }

    /**
     * Get the namespace root for an algoritm id
     *
     * @param string $algoritm
     *
     * @return string
     */
    protected function getNamespace()
    {
        return __NAMESPACE__;
    }

    /**
     * Get the namespace prefix for an algoritm id
     *
     * @param string $algoritm
     *
     * @return string|null
     */
    protected function getPrefix($algoritm)
    {
        $prefix = substr($algoritm, 0, 2);

        if (empty($this->prefixes[$prefix])) {
            return null;
        }

        return $this->prefixes[$prefix];
    }

    /**
     * Get the default class name for an algoritm id
     *
     * @param string $algoritm
     *
     * @return string
     */
    protected function getClass($algoritm)
    {
        return 'Sha' . substr($algoritm, 2);
    }

    /**
     * Register a default signer by algorithm
     *
     * @throws \InvalidArgumentException if no signer can be identified
     *
     * @param string $id
     *
     * @return void
     */
    private function registerDefaultSigner($algoritm)
    {
        $class = implode('\\', [
            $this->getNamespace($algoritm),
            $this->getPrefix($algoritm),
            $this->getClass($algoritm)
        ]);

        if (!class_exists($class)) {
            throw new \InvalidArgumentException(sprintf(
                'Unable to identify default signer for %s in %s',
                $algoritm,
                $class
            ));
        }

        $this->register(new $class);
    }

    /**
     * Get a signer by algorithm id
     *
     * @param string $algoritm
     *
     * @return \Lcobucci\JWT\Signer
     */
    public function get($algoritm)
    {
        if (empty($this->registry[$algoritm])) {
            $this->registerDefaultSigner($algoritm);
        }

        return $this->registry[$algoritm];
    }
}
