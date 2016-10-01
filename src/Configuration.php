<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * Configuration container for the JWT Builder and Parser
 *
 * Serves like a small DI container to simplify the creation and usage
 * of the objects.
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class Configuration
{
    /**
     * @var Parser|null
     */
    private $parser;

    /**
     * @var Signer|null
     */
    private $signer;

    /**
     * @var Parsing\Encoder|null
     */
    private $encoder;

    /**
     * @var Parsing\Decoder|null
     */
    private $decoder;

    public function createBuilder(): Builder
    {
        return new Builder($this->getEncoder());
    }

    public function getParser(): Parser
    {
        if ($this->parser === null) {
            $this->parser = new Parser($this->getDecoder());
        }

        return $this->parser;
    }

    public function setParser(Parser $parser)
    {
        $this->parser = $parser;
    }

    public function getSigner(): Signer
    {
        if ($this->signer === null) {
            $this->signer = new Sha256();
        }

        return $this->signer;
    }

    public function setSigner(Signer $signer)
    {
        $this->signer = $signer;
    }

    private function getEncoder(): Parsing\Encoder
    {
        if ($this->encoder === null) {
            $this->encoder = new Parsing\Parser();
        }

        return $this->encoder;
    }

    public function setEncoder(Parsing\Encoder $encoder)
    {
        $this->encoder = $encoder;
    }

    private function getDecoder(): Parsing\Decoder
    {
        if ($this->decoder === null) {
            $this->decoder = new Parsing\Parser();
        }

        return $this->decoder;
    }

    public function setDecoder(Parsing\Decoder $decoder)
    {
        $this->decoder = $decoder;
    }
}
