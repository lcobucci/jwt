<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

use InvalidArgumentException;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Signer\Factory as SignerFactory;

/**
 * This class parses the JWT strings and convert them into tokens
 *
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 0.1.0
 */
class Parser
{
    /**
     * The data encoder
     *
     * @var Encoder
     */
    private $encoder;

    /**
     * The data decoder
     *
     * @var Decoder
     */
    private $decoder;

    /**
     * The signer factory
     *
     * @var SignerFactory
     */
    private $signerFactory;

    /**
     * The claims factory
     *
     * @var ClaimFactory
     */
    private $claimFactory;

    /**
     * Initializes the object
     *
     * @param Encoder $encoder
     * @param Decoder $decoder
     * @param SignerFactory $signerFactory
     * @param ClaimFactory $claimFactory
     */
    public function __construct(
        Encoder $encoder = null,
        Decoder $decoder = null,
        SignerFactory $signerFactory = null,
        ClaimFactory $claimFactory = null
    ) {
        $this->encoder = $encoder ?: new Encoder();
        $this->decoder = $decoder ?: new Decoder();
        $this->signerFactory = $signerFactory ?: new SignerFactory();
        $this->claimFactory = $claimFactory ?: new ClaimFactory();
    }

    /**
     * Parses the JWT and returns a token
     *
     * @param string $jwt
     *
     * @return Token
     */
    public function parse($jwt)
    {
        $token = $this->createToken($this->splitJwt($jwt));
        $token->setEncoder($this->encoder);

        return $token;
    }

    /**
     * Creates the token from given data
     *
     * @param array $data
     *
     * @return Token
     */
    private function createToken(array $data)
    {
        $header = $this->parseHeader($data[0]);
        $claims = $this->parseClaims($data[1]);
        $signature = $this->parseSignature($header, $data[2]);

        foreach ($claims as $name => $value) {
            if (isset($header[$name])) {
                $header[$name] = $value;
            }
        }

        return new Token($header, $claims, $signature);
    }

    /**
     * Slipts the JWT string into an array
     *
     * @param string $jwt
     *
     * @return array
     *
     * @throws InvalidArgumentException When JWT is not a string or is invalid
     */
    protected function splitJwt($jwt)
    {
        if (!is_string($jwt)) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        $data = explode('.', $jwt);

        if (count($data) != 3) {
            throw new InvalidArgumentException('The JWT string must have two dots');
        }

        return $data;
    }

    /**
     * Parses the header from a string
     *
     * @param string $data
     *
     * @return array
     *
     * @throws InvalidArgumentException When an invalid header is informed
     */
    protected function parseHeader($data)
    {
        $header = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        if (isset($header['enc'])) {
            throw new InvalidArgumentException('Encryption is not supported yet');
        }

        return $header;
    }

    /**
     * Parses the claim set from a string
     *
     * @param string $data
     *
     * @return array
     */
    protected function parseClaims($data)
    {
        $claims = $this->decoder->jsonDecode($this->decoder->base64UrlDecode($data));

        foreach ($claims as $name => &$value) {
            $value = $this->claimFactory->create($name, $value);
        }

        return $claims;
    }

    /**
     * Returns the signature from given data
     *
     * @param array $header
     * @param string $data
     *
     * @return Signature
     */
    protected function parseSignature(array $header, $data)
    {
        if ($data == '' || !isset($header['alg']) || $header['alg'] == 'none') {
            return null;
        }

        $hash = $this->decoder->base64UrlDecode($data);

        return new Signature($this->signerFactory->create($header['alg']), $hash);
    }
}
