<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT\Signer;

use Exception;
use InvalidArgumentException;
use Lcobucci\JWT\Signer\Key\FileCouldNotBeRead;
use SplFileObject;

use function strpos;
use function substr;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 3.0.4
 */
class Key
{
    /**
     * @var string
     */
    protected $content;

    /**
     * @var string
     */
    private $passphrase;

    /**
     * @param string $content
     * @param string $passphrase
     */
    public function __construct($content, $passphrase = '')
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
     * @throws InvalidArgumentException
     */
    private function readFile($content)
    {
        $path = substr($content, 7);

        try {
            $file = new SplFileObject($path);
        } catch (Exception $exception) {
            throw FileCouldNotBeRead::onPath($path, $exception);
        }

        $content = '';

        while (! $file->eof()) {
            $content .= $file->fgets();
        }

        return $content;
    }

    /** @return string */
    public function contents()
    {
        return $this->content;
    }

    /** @return string */
    public function passphrase()
    {
        return $this->passphrase;
    }

    /**
     * @deprecated This method is no longer part of the public interface
     * @see Key::contents()
     *
     * @return string
     */
    public function getContent()
    {
        return $this->content;
    }

    /**
     * @deprecated This method is no longer part of the public interface
     * @see Key::passphrase()
     *
     * @return string
     */
    public function getPassphrase()
    {
        return $this->passphrase;
    }
}
