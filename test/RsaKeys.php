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
trait RsaKeys
{
    /**
     * @return string
     */
    protected function privateRsa()
    {
        return openssl_pkey_get_private(
            '-----BEGIN PRIVATE KEY-----' . PHP_EOL
            . 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTvwE87MtgREYL' . PHP_EOL
            . 'TL4aHhQo3ZzogmxxvMUsKnPzyxRs1YrXOSOpwN0npsXarBKKVIUMNLfFODp/vnQn' . PHP_EOL
            . '2Zp06N8XG59WAOKwvC4MfxLDQkA+JXggzHlkbVoTN+dUkdYIFqSKuAPGwiWToRK2' . PHP_EOL
            . 'SxEhij3rE2FON8jQZvDxZkiP9a4vxJO3OTPQwKredXFiObsXD/c3RtLFhKctjCyH' . PHP_EOL
            . 'OIrP0bQEsee/m7JNtG4ry6BPusN6wb+vJo5ieBYPa3c19akNq6q/nYWhplhkkJSu' . PHP_EOL
            . 'aOrL5xXEFzI5TvcvnXR568GVcxK8YLfFkdxpsXGt5rAbeh0h/U5kILEAqv8P9PGT' . PHP_EOL
            . 'ZpicKbrnAgMBAAECggEAd3yTQEQHR91/ASVfKPHMQns77eCbPVtekFusbugsMHYY' . PHP_EOL
            . 'EPdHbqVMpvFvOMRc+f5Tzd15ziq6qBdbCJm8lThLm4iU0z1QrpaiDZ8vgUvDYM5Y' . PHP_EOL
            . 'CXoZDli+uZWUTp60/n94fmb0ipZIChScsI2PrzOJWTvobvD/uso8MJydWc8zafQm' . PHP_EOL
            . 'uqYzygOfjFZvU4lSfgzpefhpquy0JUy5TiKRmGUnwLb3TtcsVavjsn4QmNwLYgOF' . PHP_EOL
            . '2OE+R12ex3pAKTiRE6FcnE1xFIo1GKhBa2Otgw3MDO6Gg+kn8Q4alKz6C6RRlgaH' . PHP_EOL
            . 'R7sYzEfJhsk/GGFTYOzXKQz2lSaStKt9wKCor04RcQKBgQDzPOu5jCTfayUo7xY2' . PHP_EOL
            . 'jHtiogHyKLLObt9l3qbwgXnaD6rnxYNvCrA0OMvT+iZXsFZKJkYzJr8ZOxOpPROk' . PHP_EOL
            . '10WdOaefiwUyL5dypueSwlIDwVm+hI4Bs82MajHtzOozh+73wA+aw5rPs84Uix9w' . PHP_EOL
            . 'VbbwaVR6qP/BV09yJYS5kQ7fmwKBgQDe2xjywX2d2MC+qzRr+LfU+1+gq0jjhBCX' . PHP_EOL
            . 'WHqRN6IECB0xTnXUf9WL/VCoI1/55BhdbbEja+4btYgcXSPmlXBIRKQ4VtFfVmYB' . PHP_EOL
            . 'kPXeD8oZ7LyuNdCsbKNe+x1IHXDe6Wfs3L9ulCfXxeIE84wy3fd66mQahyXV9iD9' . PHP_EOL
            . 'CkuifMqUpQKBgQCiydHlY1LGJ/o9tA2Ewm5Na6mrvOs2V2Ox1NqbObwoYbX62eiF' . PHP_EOL
            . '53xX5u8bVl5U75JAm+79it/4bd5RtKux9dUETbLOhwcaOFm+hM+VG/IxyzRZ2nMD' . PHP_EOL
            . '1qcpY2U5BpxzknUvYF3RMTop6edxPk7zKpp9ubCtSu+oINvtxAhY/SkcIwKBgGP1' . PHP_EOL
            . 'upcImyO2GZ5shLL5eNubdSVILwV+M0LveOqyHYXZbd6z5r5OKKcGFKuWUnJwEU22' . PHP_EOL
            . '6gGNY9wh7M9sJ7JBzX9c6pwqtPcidda2AtJ8GpbOTUOG9/afNBhiYpv6OKqD3w2r' . PHP_EOL
            . 'ZmJfKg/qvpqh83zNezgy8nvDqwDxyZI2j/5uIx/RAoGBAMWRmxtv6H2cKhibI/aI' . PHP_EOL
            . 'MTJM4QRjyPNxQqvAQsv+oHUbid06VK3JE+9iQyithjcfNOwnCaoO7I7qAj9QEfJS' . PHP_EOL
            . 'MZQc/W/4DHJebo2kd11yoXPVTXXOuEwLSKCejBXABBY0MPNuPUmiXeU0O3Tyi37J' . PHP_EOL
            . 'TUKzrgcd7NvlA41Y4xKcOqEA' . PHP_EOL
            . '-----END PRIVATE KEY-----'
        );
    }

    /**
     * @return string
     */
    protected function publicRsa()
    {
        return openssl_pkey_get_public(
            '-----BEGIN PUBLIC KEY-----' . PHP_EOL
            . 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA078BPOzLYERGC0y+Gh4U' . PHP_EOL
            . 'KN2c6IJscbzFLCpz88sUbNWK1zkjqcDdJ6bF2qwSilSFDDS3xTg6f750J9madOjf' . PHP_EOL
            . 'FxufVgDisLwuDH8Sw0JAPiV4IMx5ZG1aEzfnVJHWCBakirgDxsIlk6EStksRIYo9' . PHP_EOL
            . '6xNhTjfI0Gbw8WZIj/WuL8STtzkz0MCq3nVxYjm7Fw/3N0bSxYSnLYwshziKz9G0' . PHP_EOL
            . 'BLHnv5uyTbRuK8ugT7rDesG/ryaOYngWD2t3NfWpDauqv52FoaZYZJCUrmjqy+cV' . PHP_EOL
            . 'xBcyOU73L510eevBlXMSvGC3xZHcabFxreawG3odIf1OZCCxAKr/D/Txk2aYnCm6' . PHP_EOL
            . '5wIDAQAB' . PHP_EOL
            . '-----END PUBLIC KEY-----'
        );
    }
}
