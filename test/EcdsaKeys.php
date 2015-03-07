<?php
/**
 * This file is part of Lcobucci\JWT, a simple library to handle JWT and JWS
 *
 * @license http://opensource.org/licenses/BSD-3-Clause BSD-3-Clause
 */

namespace Lcobucci\JWT;

/**
 * @author Luís Otávio Cobucci Oblonczyk <lcobucci@gmail.com>
 * @since 2.1.0
 */
trait EcdsaKeys
{
    /**
     * @return string
     */
    protected function privateEcdsa()
    {
        return openssl_pkey_get_private(
            '-----BEGIN EC PARAMETERS-----' . PHP_EOL
            . 'BgUrgQQAJw==' . PHP_EOL
            . '-----END EC PARAMETERS-----' . PHP_EOL
            . '-----BEGIN EC PRIVATE KEY-----' . PHP_EOL
            . 'MIHuAgEBBEgDRUM4kmPRmsGwTcnIO1s9sZIHKzqwXKaveOX0NFWbP6HC8heO/2YV' . PHP_EOL
            . 'SWDgKYJa905X2j9YgZxYBSUVk+sBg6rqgjjrpDRIXWWgBwYFK4EEACehgZUDgZIA' . PHP_EOL
            . 'BAS/53Ebxy202oxYbDUMuf4r+VXe4JBZt00dOFnfAKU7iIF42vHaq11rYlny4xhm' . PHP_EOL
            . '1VC8Mp7vzVT8aAMPVyzeoxny7fukbDHutAXhPSLHoP3FqVzBzNPKyrLMGtethIF2' . PHP_EOL
            . '9GXPyg/HD96OUFnoIRzl61da4C1QpLQRY5wUUUSHvwCo3IpOBPR9PpLhp/hwb5lq' . PHP_EOL
            . 'Tw==' . PHP_EOL
            . '-----END EC PRIVATE KEY-----'
        );
    }

    /**
     * @return string
     */
    protected function publicEcdsa()
    {
        return openssl_pkey_get_public(
            '-----BEGIN CERTIFICATE-----' . PHP_EOL
            . 'MIIC3TCCAjKgAwIBAgIJAIRSqqEhTGdPMAoGCCqGSM49BAMCMHsxCzAJBgNVBAYT' . PHP_EOL
            . 'AkJSMRcwFQYDVQQIDA5TYW50YSBDYXRhcmluYTETMBEGA1UEBwwKUGFsaG/Dg8Kn' . PHP_EOL
            . 'YTETMBEGA1UECgwKRGFyd2luc29mdDEPMA0GA1UEAwwGYWEuZGV2MRgwFgYJKoZI' . PHP_EOL
            . 'hvcNAQkBFglhYUBhYS5jb20wHhcNMTUwMzA3MDIyOTM3WhcNMTYwMzA2MDIyOTM3' . PHP_EOL
            . 'WjB7MQswCQYDVQQGEwJCUjEXMBUGA1UECAwOU2FudGEgQ2F0YXJpbmExEzARBgNV' . PHP_EOL
            . 'BAcMClBhbGhvw4PCp2ExEzARBgNVBAoMCkRhcndpbnNvZnQxDzANBgNVBAMMBmFh' . PHP_EOL
            . 'LmRldjEYMBYGCSqGSIb3DQEJARYJYWFAYWEuY29tMIGnMBAGByqGSM49AgEGBSuB' . PHP_EOL
            . 'BAAnA4GSAAQEv+dxG8cttNqMWGw1DLn+K/lV3uCQWbdNHThZ3wClO4iBeNrx2qtd' . PHP_EOL
            . 'a2JZ8uMYZtVQvDKe781U/GgDD1cs3qMZ8u37pGwx7rQF4T0ix6D9xalcwczTysqy' . PHP_EOL
            . 'zBrXrYSBdvRlz8oPxw/ejlBZ6CEc5etXWuAtUKS0EWOcFFFEh78AqNyKTgT0fT6S' . PHP_EOL
            . '4af4cG+Zak+jUDBOMB0GA1UdDgQWBBTr67eZAsb3gl+2GN5zubBTH2JZVDAfBgNV' . PHP_EOL
            . 'HSMEGDAWgBTr67eZAsb3gl+2GN5zubBTH2JZVDAMBgNVHRMEBTADAQH/MAoGCCqG' . PHP_EOL
            . 'SM49BAMCA4GYADCBlAJIASbENQZGlxky0cVbPyEnolSbYaX7vmXS64cQ0jjZWng4' . PHP_EOL
            . 'nVauE803oH1kQTpLedDvGnz5Gl+w2uKpkTlGvYv0IrE6CBPtxsc9AkgCtO4RDWWd' . PHP_EOL
            . 'xVKqbZZ9XN5PkdWD12g3xWwYcxgWVI++r4FHRZKE8izH9Mw+lDTrkJJ+G80Q9r24' . PHP_EOL
            . 'zI1qdkGoueCawNCmGHpl0VE=' . PHP_EOL
            . '-----END CERTIFICATE-----'
        );
    }
}
