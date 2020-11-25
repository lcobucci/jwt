# Installation

This package is available on [Packagist] and you can install it using [Composer].

By running the following command you'll add `lcobucci/jwt` as a dependency to your project:

```sh
composer require lcobucci/jwt
```

## Autoloading

!!! Note
    We'll be omitting the autoloader from the code samples to simplify the documentation.

In order to be able to use the classes provided by this library you're also required to include [Composer]'s autoloader in your application:

```php
require 'vendor/bin/autoload.php';
```

!!! Tip
    If you're not familiar with how [composer] works, we highly recommend you to take some time to read it's documentation - especially the [autoloading section].

[Packagist]: https://packagist.org/packages/lcobucci/jwt
[Composer]: https://getcomposer.org
[autoloading section]: https://getcomposer.org/doc/01-basic-usage.md#autoloading
