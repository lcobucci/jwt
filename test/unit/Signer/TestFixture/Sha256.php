<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer\TestFixture;

use Lcobucci\JWT\Signer\Hmac\Sha256 as Alias;

/**
 * Test Signer for HMAC SHA-256
 *
 * @author Woody Gilk <@shadowhand>
 * @since 3.0.6
 */
class Sha256 extends Alias
{
    /**
     * {@inheritdoc}
     */
    public function getAlgorithmId()
    {
        return 'TF256';
    }

    /**
     * {@inheritdoc}
     */
    public function getAlgorithm()
    {
        return 'tf256';
    }
}
