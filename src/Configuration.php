<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

declare(strict_types=1);

namespace Lcobucci\JWT;

use Lcobucci\Jose\Parsing;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Signer\Hmac\Sha256;

/**
 * Configuration container for the JWT Builder and Parser
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 4.0.0
 */
final class Configuration
{
    /**
     * @var array
     */
    private $data;

    public function __construct()
    {
        $this->data = [];
    }

    public function createBuilder(): Builder
    {
        return new Builder($this->getEncoder(), $this->getClaimFactory());
    }

    public function getParser(): Parser
    {
        if (!array_key_exists('parser', $this->data)) {
            $this->data['parser'] = new Parser($this->getDecoder(), $this->getClaimFactory());
        }

        return $this->data['parser'];
    }

    public function setParser(Parser $parser)
    {
        $this->data['parser'] = $parser;
    }

    public function getSigner(): Signer
    {
        if (!array_key_exists('signer', $this->data)) {
            $this->data['signer'] = new Sha256();
        }

        return $this->data['signer'];
    }

    public function setSigner(Signer $signer)
    {
        $this->data['signer'] = $signer;
    }

    private function getClaimFactory(): ClaimFactory
    {
        if (!array_key_exists('claimFactory', $this->data)) {
            $this->data['claimFactory'] = new ClaimFactory();
        }

        return $this->data['claimFactory'];
    }

    public function setClaimFactory(ClaimFactory $claimFactory)
    {
        $this->data['claimFactory'] = $claimFactory;
    }

    public function setEncoder(Parsing\Encoder $encoder)
    {
        $this->data['encoder'] = $encoder;
    }

    private function getEncoder(): Parsing\Encoder
    {
        if (!array_key_exists('encoder', $this->data)) {
            $this->data['encoder'] = new Parsing\Parser();
        }

        return $this->data['encoder'];
    }

    public function setDecoder(Parsing\Decoder $decoder)
    {
        $this->data['decoder'] = $decoder;
    }

    private function getDecoder(): Parsing\Decoder
    {
        if (!array_key_exists('decoder', $this->data)) {
            $this->data['decoder'] = new Parsing\Parser();
        }

        return $this->data['decoder'];
    }
}
