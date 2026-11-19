<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Token;

/**
 * Defines the list of claims that are registered in the IANA "JSON Web Token Claims" registry
 *
 * @see https://tools.ietf.org/html/rfc7519#section-4.1
 */
interface RegisteredClaims
{
    public const array ALL = [
        self::AUDIENCE,
        self::EXPIRATION_TIME,
        self::ID,
        self::ISSUED_AT,
        self::ISSUER,
        self::NOT_BEFORE,
        self::SUBJECT,
    ];

    public const array DATE_CLAIMS = [
        self::ISSUED_AT,
        self::NOT_BEFORE,
        self::EXPIRATION_TIME,
    ];

    /**
     * Identifies the recipients that the JWT is intended for
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.3
     */
    public const string AUDIENCE = 'aud';

    /**
     * Identifies the expiration time on or after which the JWT MUST NOT be accepted for processing
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.4
     */
    public const string EXPIRATION_TIME = 'exp';

    /**
     * Provides a unique identifier for the JWT
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.7
     */
    public const string ID = 'jti';

    /**
     * Identifies the time at which the JWT was issued
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.6
     */
    public const string ISSUED_AT = 'iat';

    /**
     * Identifies the principal that issued the JWT
     *
     * @see https://tools.ietf.org/html/rfc7519#section-4.1.1
     */
    public const string ISSUER = 'iss';

    /**
     * Identifies the time before which the JWT MUST NOT be accepted for processing
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.5
     */
    public const string NOT_BEFORE = 'nbf';

    /**
     * Identifies the principal that is the subject of the JWT.
     *
     * https://tools.ietf.org/html/rfc7519#section-4.1.2
     */
    public const string SUBJECT = 'sub';
}
