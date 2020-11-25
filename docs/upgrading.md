# Upgrading steps

Here we'll keep a list of all steps you need to take to make sure your code is compatible with newer versions.

## v3.x to v4.x

The `v4.0.0` aggregates about 5 years of work and contains **several BC-breaks**.
We're building on the version `v3.4.0` a forward compatibility layer to help users to migrate to `v4.0.0`.

To help on the migration process, all deprecated components are being marked with `@deprecated` and deprecated behaviour will trigger a `E_USER_DEPRECATED` error.
However, you can also find here the instructions on how to make your code compatible with both versions.

### Inject the configuration object instead of builder/parser/key

This object serves as a small service locator that centralises the JWT-related dependencies.
The main goal is to simplify the injection of our components into downstream code.

This step is quite important to at least have a single way to initialise the JWT components, even if the configuration object is thrown away.

Check an example of how to migrate the injection of builder+signer+key to configuration object below: 

```diff
 <?php
 declare(strict_types=1);
 
 namespace Me\MyApp\Authentication;
 
-use Lcobucci\JWT\Builder;
 use Lcobucci\JWT\Configuration;
-use Lcobucci\JWT\Signer;
-use Lcobucci\JWT\Signer\Key;
 use Lcobucci\JWT\Token;
 
 use function bin2hex;
 use function random_bytes;
 
 final class JwtIssuer
 {
-    private Builder $builder;
-    private Signer $signer;
-    private Key $key;
- 
-    public function __construct(Builder $builder, Signer $signer, Key $key)
-    {
-        $this->builder = $builder;
-        $this->signer  = $signer;
-        $this->key     = $key;
-    }   
+    private Configuration $config;
+    
+    public function __construct(Configuration $config)
+    {
+        $this->config = $config;
+    }
    
     public function issueToken(): Token
     {
-        return $this->builder
+        return $this->config->builder()
             ->identifiedBy(bin2hex(random_bytes(16)))
-            ->getToken($this->signer, $this->key);
+            ->getToken($this->config->signer(), $this->config->signingKey());
     }
 }
```

You can find more information on how to use the configuration object, [here](configuration.md).

### Use new `Key` objects

`Lcobucci\JWT\Signer\Key` has been converted to an interface in `v4.0`.
We provide two new implementations: `Lcobucci\JWT\Signer\Key\InMemory` and `Lcobucci\JWT\Signer\Key\LocalFileReference`.

`Lcobucci\JWT\Signer\Key\InMemory` is a drop-in replacement of the behaviour for `Lcobucci\JWT\Signer\Key` in `v3.x`.
You will need to pick the appropriated named constructor to migrate your code:

```diff
 <?php
 declare(strict_types=1);
 
 namespace Me\MyApp\Authentication;
 
-use Lcobucci\JWT\Signer\Key;
+use Lcobucci\JWT\Signer\Key\InMemory;
-
-use function base64_decode;
 
 // Key from plain text
-$key = new Key('a-very-secure-key');
+$key = InMemory::plainText('a-very-secure-key');
 
 // Key from base64 encoded string
-$key = new Key(base64_decode('YS12ZXJ5LXNlY3VyZS1rZXk=', true));
+$key = InMemory::base64Encoded('YS12ZXJ5LXNlY3VyZS1rZXk=');
 
 // Key from file contents
-$key = new Key('file:///var/secrets/my-private-key.pem');
+$key = InMemory::file('/var/secrets/my-private-key.pem');
```

### Use the new `Builder` API

There are 4 main differences on the new API:

1. Token configuration methods were renamed
1. Signature is created via `Builder#getToken()` (instead of `Builder#sign()`)
1. `DateTimeImmutable` objects are now for the registered claims with dates
1. Headers should be replicated manually - whenever necessary

Here's the migration:

```diff
 <?php
 declare(strict_types=1);
 
 namespace Me\MyApp\Authentication;

+use DateTimeImmutable; 
-use Lcobucci\JWT\Builder;
+use Lcobucci\JWT\Configuration;
+use Lcobucci\JWT\Signer\Key\InMemory;
 use Lcobucci\JWT\Signer\Hmac\Sha256;
-
-use function time;

-$now = time();
+$now = new DateTimeImmutable();
+$config = Configuration::forSymmetricSigner(new Sha256(), InMemory::plainText('testing'));

-$token = (new Builder())
+$token = $config->builder()
-    ->setIssuer('http://example.com', true)
+    ->issuedBy('http://example.com')
+    ->withHeader('iss', 'http://example.com')
-    ->setAudience('http://example.org')
+    ->permittedFor('http://example.org')
-    ->setId('4f1g23a12aa')
+    ->identifiedBy('4f1g23a12aa')
-    ->setSubject('user123')
+    ->relatedTo('user123')
-    ->setIssuedAt($now)
+    ->issuedAt($now)
-    ->setNotBefore($now + 60)
+    ->canOnlyBeUsedAfter($now->modify('+1 minute'))
-    ->setExpiration($now + 3600)
+    ->expiresAt($now->modify('+1 hour'))
-    ->set('uid', 1)
+    ->withClaim('uid', 1)
-    ->sign(new Sha256(), 'testing')
-    ->getToken();
+    ->getToken($config->signer(), $config->signingKey());
```

### Replace `Token#verify()` and `Token#validate()` with Validation API

These methods were quite limited and brings multiple responsibilities to the `Token` class.
On `v4.0` we provide another component to validate tokens, including their signature.

Here's an example of how to modify that logic (considering [constraints have been configured](configuration.md#customisation)):

```diff
 <?php
 declare(strict_types=1);
 
 namespace Me\MyApp\Authentication;
 
 use InvalidArgumentException;
+use Lcobucci\JWT\Configuration;
-use Lcobucci\JWT\Signer;
-use Lcobucci\JWT\Signer\Key;
-use Lcobucci\JWT\Parser;
-use Lcobucci\JWT\ValidationData;
 
 final class AuthenticateJwt
 {
-    private Parser $parser;
-    private Signer $signer;
-    private Key $key;
+    private Configuration $config;
     
-    public function __construct(Parser $parser, Signer $signer, Key $key)
+    public function __construct(Configuration $config)
     {
-        $this->parser = $parser;
-        $this->signer = $signer;
-        $this->key    = $key;
+        $this->config = $config;
     }
     
     public function authenticate(string $jwt): void
     {
-        $token = $this->parser->parse($jwt);
+        $token = $this->config->parser()->parse($jwt);
         
-        if (! $token->validate(new ValidationData()) || $token->verify($this->signer, $this->key)) {
+        if (! $this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
             throw new InvalidArgumentException('Invalid token provided');
         }
     }
 }
```

Check [here](validating-tokens.md) for more information on how to validate tokens and what are the built-in constraints.

### Use the new `Token` API

There some important differences on this new API:

1. We no longer use the `Lcobucci\JWT\Claim` objects
1. Headers and claims are now represented as `Lcobucci\JWT\Token\DataSet`
1. Different methods should be used to retrieve a header/claim
1. No exception is thrown when accessing missing header/claim, the default argument is always used
1. Tokens should be explicitly casted to string via method

Your code should be adapted to manipulate tokens like this:

```diff
 <?php
 declare(strict_types=1);
 
 namespace Me\MyApp\Authentication;
 
 // we assume here that $token is a valid parsed/created token
 
-$token->getHeaders() 
+$token->headers()->all()
-$token->hasHeader('typ')
+$token->headers()->has('typ')
-$token->getHeader('typ')
+$token->headers()->get('typ')

-$token->getClaims() 
+$token->claims()->all()
-$token->hasClaim('iss')
+$token->claims()->has('iss')
-$token->getClaim('iss')
+$token->claims()->get('iss')

-echo (string) $token;
+echo $token->toString();
```
