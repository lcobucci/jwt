<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT\Validation;

/**
 * Basic interface describing validation results
 */
interface ResultsInterface
{
    /**
     * Returns true on valid results
     *
     * @return bool
     */
    public function valid(): bool;

    /**
     * Returns an array with name => message
     *
     * @return array
     */
    public function errors(): array;
}
