<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use InvalidArgumentException;
use JsonSerializable;
use PHPUnit_Framework_TestCase;

final class ClaimValueTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     *
     * @uses Lcobucci\JWT\ClaimValue
     *
     * @covers Lcobucci\JWT\ClaimValue::__construct
     * @covers Lcobucci\JWT\ClaimValue::jsonSerialize
     * @covers Lcobucci\JWT\ClaimValue::ensureValueIsJsonSerializable
     *
     * @dataProvider getValidValues
     */
    public function constructorMakesSureValueIsJsonSerializable($value)
    {
        $claimValue = new ClaimValue($value);

        $this->assertSame($value, $claimValue->jsonSerialize());
    }

    public function getValidValues()
    {
        return [
            ['a'],
            [true],
            [1],
            [1.1],
            [
                new class implements JsonSerializable {
                    function jsonSerialize()
                    {
                    }
                }
            ],
            [
                [
                    1,
                    'a',
                    true,
                    1.2,
                    [
                        1,
                        'a',
                        [
                            'foo',
                            new class implements JsonSerializable {
                                function jsonSerialize()
                                {
                                }
                            }
                        ]
                    ]
                ]
            ],
        ];
    }

    /**
     * @test
     *
     * @uses Lcobucci\JWT\ClaimValue
     *
     * @covers Lcobucci\JWT\ClaimValue::__construct
     *
     * @dataProvider getInvalidData
     * @expectedException InvalidArgumentException
     */
    public function constructorMakesSureValueIsJsonSerializableAndThrowsExceptionWhenUsingInvalidValue($value)
    {
        new ClaimValue($value);
    }

    public function getInvalidData()
    {

        return [
            [
                new class()
                {
                }
            ],
            [
                fopen('php://memory', 'r+')
            ],
            [
                [
                    '1',
                    false,
                    [
                        'b',
                        fopen('php://memory', 'r+')
                    ]
                ]
            ]
        ];
    }
}
