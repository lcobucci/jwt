<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Signer\Ecdsa;

use PHPUnit\Framework\TestCase;

abstract class BaseTestCase extends TestCase
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
