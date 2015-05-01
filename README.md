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
