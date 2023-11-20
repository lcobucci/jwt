# Rotating Keys

Key rotation consists in retiring and replacing cryptographic keys with new ones.
Performing that operation on a regular basis is an industry standard.

## Why should I rotate my keys?

Rotating keys allows us to:

1. Limit the number of tokens signed with the same key, helping the prevention of attacks enabled by cryptanalysis
2. Adopt other algorithms or stronger keys
3. Limit the impact of eventual compromised keys

## The challenges

After rotating keys, apps will likely receive requests with tokens issues with the previous key.
If the key rotation of an app is done with a "hard cut", requests with non-expired tokens issued with the old key **will fail**!

Imagine if you were the user who logged in just before a key rotation on that kind of app, you'd probably have to log in again!

That's rather frustrating, right!?

## Preventing issues

It's possible to handle key rotation in a smoother way by leveraging the `SignedWithOneInSet` validation constraint!

Say your application uses the symmetric algorithm `HS256` with a not so secure key to issue tokens:

```php
<?php
declare(strict_types=1);

namespace MyApp;

require 'vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;

// `FrozenClock` is used here to fix to a point in time that allows our validation to pass
$clock = new FrozenClock(new DateTimeImmutable('2023-11-04 21:06:01+00:00')); 
$token = (new JwtFacade(clock: $clock))->issue(
    new Signer\Hmac\Sha256(),
    InMemory::plainText(
        'a-very-long-and-secure-key-that-should-actually-be-something-else'
    ),
    static fn (Builder $builder): Builder => $builder
        ->issuedBy('https://api.my-awesome-app.io')
        ->permittedFor('https://client-app.io')
);
```

!!! Sample
    Here's a token issued with the code above, if you want to test the script locally:

    <details>
        <summary>Sample token</summary>
        
        // line breaks added for readability
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
        .eyJpYXQiOjE2OTkxMzE5NjEsIm5iZiI6MTY5OTEzMTk2MSwiZXhwIjoxNjk5MTMyMjYxLCJpc3MiOiJ
        odHRwczovL2FwaS5teS1hd2Vzb21lLWFwcC5pbyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LWFwcC5pbyJ9
        .IA9S0n8Q2O97lyR8KczVE8g-hxbbH6_TfJS-JWTQR4c
    </details>

Your parsing logic (with validations) look like:

```php
<?php
declare(strict_types=1);

namespace MyApp;

require 'vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;

// `FrozenClock` is used here to fix to a point in time that allows our
// validation to pass
$clock = new FrozenClock(new DateTimeImmutable('2023-11-04 21:06:35+00:00'))

$validationConstraints = [
    new Constraint\SignedWith(
        new Signer\Hmac\Sha256(),
        InMemory::plainText(
            'a-very-long-and-secure-key-that-should-actually-be-something-else'
        ),
    ),
    new Constraint\StrictValidAt($clock),
];

$jwt = ''; // Fetched from, for example, a request header

$token = (new JwtFacade())->parse($jwt, ...$validationConstraints);
```

### Performing a backwards compatible rotation

Now Imagine that you want to adopt the new `BLAKE2B` symmetric algorithm.

These are the changes to your issuing logic:

```diff
 <?php
 declare(strict_types=1);
 
 namespace MyApp;
 
 require 'vendor/autoload.php';
 
 use DateTimeImmutable;
 use Lcobucci\Clock\FrozenClock;
 use Lcobucci\JWT\Builder;
 use Lcobucci\JWT\JwtFacade;
 use Lcobucci\JWT\Signer;
 use Lcobucci\JWT\Signer\Key\InMemory;
 
 // `FrozenClock` is used here to fix to a point in time that allows our validation to pass
 $clock = new FrozenClock(new DateTimeImmutable('2023-11-04 21:06:01+00:00')); 
 $token = (new JwtFacade(clock: $clock))->issue(
-    new Signer\Hmac\Sha256(),
+    new Signer\Blake2b(),
-    InMemory::plainText(
-        'a-very-long-and-secure-key-that-should-actually-be-something-else'
+    InMemory::base64Encoded(
+        'GOu4rLyVCBxmxP+sbniU68ojAja5PkRdvv7vNvBCqDQ='
     ),
     static fn (Builder $builder): Builder => $builder
         ->issuedBy('https://api.my-awesome-app.io')
         ->permittedFor('https://client-app.io')
 );
```

!!! Sample
    Here's a token issued with the code above, if you want to test the script locally:

    <details>
        <summary>Sample token</summary>
        
        // line breaks added for readability
        eyJ0eXAiOiJKV1QiLCJhbGciOiJCTEFLRTJCIn0
        .eyJpYXQiOjE2OTkxMzE5NjEsIm5iZiI6MTY5OTEzMTk2MSwiZXhwIjoxNjk5MTMyMjYxLCJpc3Mi
        OiJodHRwczovL2FwaS5teS1hd2Vzb21lLWFwcC5pbyIsImF1ZCI6Imh0dHBzOi8vY2xpZW50LWFwc
        C5pbyJ9.bD67s8IXpAJiBTIZn1et_M5WSS7kfmuNiacNRz5lArQ
    </details>

So far, nothing different that a normal rotation.

Now check the changes on the parsing and validation logic:

```diff
 <?php
 declare(strict_types=1);
 
 namespace MyApp;
 
 require 'vendor/autoload.php';
 
 use DateTimeImmutable;
 use Lcobucci\Clock\FrozenClock;
 use Lcobucci\JWT\JwtFacade;
 use Lcobucci\JWT\Signer;
 use Lcobucci\JWT\Signer\Key\InMemory;
 use Lcobucci\JWT\Validation\Constraint;

 // `FrozenClock` is used here to fix to a point in time that allows our
 // validation to pass
 $clock = new FrozenClock(new DateTimeImmutable('2023-11-04 21:06:35+00:00'));
 
 $validationConstraints = [
-    new Constraint\SignedWith(
-        new Signer\Hmac\Sha256(),
-        InMemory::plainText(
-            'a-very-long-and-secure-key-that-should-actually-be-something-else'
-        ),
-    ),
+    new Constraint\SignedWithOneInSet(
+       new Constraint\SignedWithUntilDate(
+           new Signer\Blake2b(),
+           InMemory::base64Encoded(
+               'GOu4rLyVCBxmxP+sbniU68ojAja5PkRdvv7vNvBCqDQ='
+           ),
+           new DateTimeImmutable('2025-12-31 23:59:59+00:00'),
+           $clock,
+       ),
+       new Constraint\SignedWithUntilDate(
+            new Signer\Hmac\Sha256(),
+           InMemory::plainText(
+                'a-very-long-and-secure-key-that-should-actually-be-something-else'
+           ),
+           new DateTimeImmutable('2023-12-31 23:59:59+00:00'),
+           $clock,
+       ),
+    ),
     new Constraint\StrictValidAt($clock),
 ];
 
 $jwt = ''; // Fetched from, for example, a request header
 
 $token = (new JwtFacade())->parse($jwt, ...$validationConstraints);
```

Now the application is able to accept non-expired tokens issued with either old and new keys!
In this case, the old key would automatically only be accepted until `2023-12-31 23:59:59+00:00`, even if engineers forget to remove it from the list.

!!! Important
    The order of `SignedWithUntilDate` constraints given to `SignedWithOneInSet` does matter, and it's recommended to leave older keys at the end of the list.
