<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use InvalidArgumentException;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 3.0.4
 */
final class Key
{
    /**
     * @var string
     */
    private $content;

    /**
     * @var string
     */
    private $passphrase;

    /**
     * @param string $content
     * @param string $passphrase
     */
    public function __construct($content, $passphrase = null)
    {
        $this->setContent($content);
        $this->passphrase = $passphrase;
    }

    /**
     * @param string $content
     *
     * @throws InvalidArgumentException
     */
    private function setContent($content)
    {
        if (strpos($content, 'file://') === 0) {
            $content = $this->readFile($content);
        }

        $this->content = $content;
    }

    /**
     * @param string $content
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function readFile($content)
    {
        $file = substr($content, 7);

        if (!is_readable($file)) {
            throw new \InvalidArgumentException('You must inform a valid key file');
        }

        return file_get_contents($file);
    }

    /**
     * @return string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * @return string
     */
    public function getPassphrase()
    {
        return $this->passphrase;
    }
}
