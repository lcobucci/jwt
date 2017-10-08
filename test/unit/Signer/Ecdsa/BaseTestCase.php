<?php

declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
abstract class BaseTestCase extends \PHPUnit\Framework\TestCase
{
    /**
     * @var EccAdapter|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $adapter;

    /**
     * @var KeyParser|\PHPUnit_Framework_MockObject_MockObject
     */
    protected $keyParser;

    /**
     * @before
     */
    public function createDependencies(): void
    {
        $this->adapter   = $this->createMock(EccAdapter::class);
        $this->keyParser = $this->createMock(KeyParser::class);
    }
}
