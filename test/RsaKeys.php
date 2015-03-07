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
    protected function encryptedPrivateRsaContent()
    {
        return '-----BEGIN RSA PRIVATE KEY-----' . PHP_EOL
               . 'Proc-Type: 4,ENCRYPTED' . PHP_EOL
               . 'DEK-Info: AES-128-CBC,0D71668CE71033CB9150ED82FC87F4A1' . PHP_EOL
               . '' . PHP_EOL
               . 'uLzPNDdlHnZ77tAGMHyPYERDMBcdV4SsQJYcSjiHhR2o0dLGTdgOpQrXTHPX4GJF' . PHP_EOL
               . 'LlEWLhAAV9wx2mM/2kHDWB4uZwThtT9/v+RFoW1WbVO/d3lhI9fg4/73/DWAH/7/' . PHP_EOL
               . 'afMRc7ZOVoAmVCESotPx4khCHoE97RdY/JtkLTzc3+peqmL53AbYXrg9rTN1B+ZV' . PHP_EOL
               . 'U3w4ciQS8Uki87zDYIBjYtaOCyMUTvug25CvdssvUMBoc/Jc0xps6/vAyXrnzlGT' . PHP_EOL
               . 'pZD0Tst8idswfDi613BhAaxJspeY0AErWA59qJ3eGzbiQq5RDWcbJe/Tz5r/6+NN' . PHP_EOL
               . 'DkvNQ7DaEZ6LpeWX0MUq6/QWfrM8yE95XhjyC1d3LYn32lXHUygbgTFWIgLDoOE6' . PHP_EOL
               . 'nBhu34SWtbLAnqYGewaJFxhlYVS9rb/uvYQg70r5X9Sx6alCQPiPyIv39IItezn2' . PHP_EOL
               . 'HF2GRfE91MPZUeDhdqdvvOlSZVM5KnYc1fhamGAwM48gdDDXe8Czu/JEGoANNvC3' . PHP_EOL
               . 'l/Z1p5RtGF4hrel9WpeX9zQq3pvtfVcVIiWuRUwCOSQytXlieRK37sMuYeggvmjV' . PHP_EOL
               . 'VvaCods3mS/panWg9T/D/deIXjhzNJLvyiJg8+3sY5H4yNe0XpbaAc/ySwt9Rcxy' . PHP_EOL
               . 'FzFQ+5pghLSZgR1uV3AhdcnzXBU2GkYhdGKt2tUsH0UeVQ2BXxTlBFsCOh2dWqcj' . PHP_EOL
               . 'y3suIG65bukDAAWidQ4q3S6ZIMpXBhhCj7nwB5jQ7wSlU3U9So0ndr7zxdUILiMm' . PHP_EOL
               . 'chHi3q5apVZnMGcwv2B33rt4nD7HgGEmRKkCelrSrBATY1ut+T4rCDzKDqDs3jpv' . PHP_EOL
               . 'hYIWrlNPTkJyQz3eWly6Db+FJEfdYGadYJusc7/nOxCh/QmUu8Sh3NhKT6TH0bS7' . PHP_EOL
               . '1AAqd8H+2hJ9I32Dhd2qwAF7PkNe2LGi+P8tbAtepKGim5w65wnsPePMnrfxumsG' . PHP_EOL
               . 'PeDnMrqeCKy+fME7a/MS5kmEBpmD4BMhVC6/OhFVz8gBty1f8yIEZggHNQN2QK7m' . PHP_EOL
               . 'NIrG+PwqW2w8HoxOlAi2Ix4LTPifrdfsH02U7aM1pgo1rZzD4AOzqvzCaK43H2VB' . PHP_EOL
               . 'BHLeTBGoLEUxXA9C+iGbeQlKXkMC00QKkjK5+nvkvnvePFfsrTQIpuyGufD/MoPb' . PHP_EOL
               . '6fpwsyHZDxhxMN1PJk1b1lPq2Ui4hXpVNOYd4Q6OQz7bwxTMRX9XQromUlKMMgAT' . PHP_EOL
               . 'edX8v2NdM7Ssy1IwHuGVbDEpZdjoeaWZ1iNRV17i/EaJAqwYDQLfsuHBlzZL1ov1' . PHP_EOL
               . 'xkKVJdL8Y3q80oRAzTQDVdzL/rI44LLAfv609YByCnw29feYJY2W6gV0O7ZSw413' . PHP_EOL
               . 'XUkc5CaEbR1LuG8NtnOOPJV4Tb/hNsIDtvVm7Hl5npBKBe4iVgQ2LNuC2eT69d/z' . PHP_EOL
               . 'uvzgjISlumPiO5ivuYe0QtLPuJSc+/Bl8bPL8gcNQEtqkzj7IftHPPZNs+bJC2uY' . PHP_EOL
               . 'bPjq5KoDNAMF6VHuKHwu48MBYpnXDIg3ZenmJwGRULRBhK6324hDS6NJ7ULTBU2M' . PHP_EOL
               . 'TZCHmg89ySLBfCAspVeo63o/R7bs9a7BP9x2h5uwCBogSvkEwhhPKnboVN45bp9c' . PHP_EOL
               . '-----END RSA PRIVATE KEY-----';
    }

    /**
     * @return string
     */
    protected function privateRsaContent()
    {
        return '-----BEGIN PRIVATE KEY-----' . PHP_EOL
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
               . '-----END PRIVATE KEY-----';
    }

    /**
     * @return string
     */
    protected function publicRsaContent()
    {
        return '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA078BPOzLYERGC0y+Gh4U' . PHP_EOL
               . 'KN2c6IJscbzFLCpz88sUbNWK1zkjqcDdJ6bF2qwSilSFDDS3xTg6f750J9madOjf' . PHP_EOL
               . 'FxufVgDisLwuDH8Sw0JAPiV4IMx5ZG1aEzfnVJHWCBakirgDxsIlk6EStksRIYo9' . PHP_EOL
               . '6xNhTjfI0Gbw8WZIj/WuL8STtzkz0MCq3nVxYjm7Fw/3N0bSxYSnLYwshziKz9G0' . PHP_EOL
               . 'BLHnv5uyTbRuK8ugT7rDesG/ryaOYngWD2t3NfWpDauqv52FoaZYZJCUrmjqy+cV' . PHP_EOL
               . 'xBcyOU73L510eevBlXMSvGC3xZHcabFxreawG3odIf1OZCCxAKr/D/Txk2aYnCm6' . PHP_EOL
               . '5wIDAQAB' . PHP_EOL
               . '-----END PUBLIC KEY-----';
    }

    /**
     * @return string
     */
    protected function encryptedPublicRsaContent()
    {
        return '-----BEGIN PUBLIC KEY-----' . PHP_EOL
               . 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLpbUP8a9yflt5LKUUS3' . PHP_EOL
               . 'NPuRM7yEouPWg0VKeY5AURu4i8bqQ20K5jwfRJ+w05FvlywG4EuxpnpTFTVS2/do' . PHP_EOL
               . 'q3xufzTf/C3KIDOAHEifkdx4140btKxxm4mD9Eu2CQ32adZyScha50KUFlfnAAic' . PHP_EOL
               . 'Hb8wYxjFyWo3PAbGYmCQCn2z97Ab0Ar6NR1e+V9f8EL9Orr2f04puKJfQTZdWVDF' . PHP_EOL
               . 'UJR4w7QZ/CPY0LEsiFLW3QQCNraka1mtrLJwPqreBtDEkj8IoISNkrguu/97RQZz' . PHP_EOL
               . 'miJgBQkVjr6OfqG5WIFr0MzbRZc1/aK9g8ft88nhhQm0E3GqkCxBKTwgA03HtK07' . PHP_EOL
               . 'qQIDAQAB' . PHP_EOL
               . '-----END PUBLIC KEY-----';
    }

    /**
     * @return string
     */
    protected function privateRsa()
    {
        return openssl_pkey_get_private($this->privateRsaContent());
    }

    /**
     * @return string
     */
    protected function encryptedPrivateRsa()
    {
        return openssl_pkey_get_private($this->encryptedPrivateRsaContent(), 'testing');
    }

    /**
     * @return string
     */
    protected function publicRsa()
    {
        return openssl_pkey_get_public($this->publicRsaContent());
    }

    /**
     * @return string
     */
    protected function encryptedPublicRsa()
    {
        return openssl_pkey_get_public($this->encryptedPublicRsaContent());
    }
}
