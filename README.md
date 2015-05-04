# cose-php
Constrained Object Signing and Encryption for PHP

### Specification

* https://datatracker.ietf.org/doc/draft-bormann-jose-cose/

### Installation

At first, install composer.

```
$ mkdir workspace
$ cd workspace
$ curl -s http://getcomposer.org/installer | php
```

Create composer.json.

```
{
    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/kura-lab/cose-php"
        }
    ],
    "require": {
        "kura-lab/cose-php": "dev-master"
    }
}
```

Install cose library.

```
$ php composer.phar install
```

### Development

Check coding style with CodeSniffer.

```
$ vendor/bin/phpcs --standard=PSR2 src/
```

Execute unit test with PHPUnit.

```
$ vendor/bin/phpunit
```

Fix source code with PHP Coding Standards Fixer.

```
$ vendor/bin/php-cs-fixer fix --config-file .php_cs --verbose --diff --dry-run
$ vendor/bin/php-cs-fixer fix --config-file .php_cs --verbose --diff
```
