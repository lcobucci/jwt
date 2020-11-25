<?php

namespace Lcobucci\JWT;

use PHPUnit\Framework\Assert;
use function class_exists;
use function restore_error_handler;
use function set_error_handler;
use const E_USER_DEPRECATED;

trait CheckForDeprecations
{
    /** @var string[]|null */
    private $expectedDeprecationMessages;

    /** @var string[]|null */
    private $actualDeprecationMessages = [];

    /** @after */
    public function verifyDeprecationWasTrigger()
    {
        if ($this->expectedDeprecationMessages === null) {
            return;
        }

        restore_error_handler();

        if (class_exists(\PHPUnit_Framework_Error_Deprecated::class)) {
            \PHPUnit_Framework_Error_Deprecated::$enabled = true;
        } else {
            \PHPUnit\Framework\Error\Deprecated::$enabled = true;
        }

        Assert::assertSame($this->expectedDeprecationMessages, $this->actualDeprecationMessages);

        $this->expectedDeprecationMessages = null;
        $this->actualDeprecationMessages   = [];
    }

    public function expectDeprecation($message)
    {
        if ($this->expectedDeprecationMessages !== null) {
            $this->expectedDeprecationMessages[] = $message;

            return;
        }

        if (class_exists(\PHPUnit_Framework_Error_Deprecated::class)) {
            \PHPUnit_Framework_Error_Deprecated::$enabled = true;
        } else {
            \PHPUnit\Framework\Error\Deprecated::$enabled = true;
        }

        $this->expectedDeprecationMessages = [$message];

        set_error_handler(
            function ($errorNumber, $message) {
                $this->actualDeprecationMessages[] = $message;
            },
            E_USER_DEPRECATED
        );
    }
}
