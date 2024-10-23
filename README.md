# Flowpack.Cors

<!-- TOC -->
* [Flowpack.Cors](#flowpackcors)
  * [Introduction](#introduction)
  * [Background](#background)
  * [Installation](#installation)
  * [Configuration](#configuration)
    * [Enable CORS in Production:](#enable-cors-in-production)
    * [Add additional allowed headers (e.g. `Authorization`):](#add-additional-allowed-headers-eg-authorization)
    * [Configuration reference](#configuration-reference)
<!-- TOC -->

## Introduction

Fully featured CORS HTTP component (a.k.a. middleware) for Flow framework to allow "cross-domain" requests.

## Background

This package is a implementation of a CORS middleware for Cross-Origin Resource Sharing (
see https://developer.mozilla.org/en-US/docs/Glossary/CORS).
This enables the client (browser) of a webapp to perform "cross-domain" requests.

The work is partially based on the awesome [github.com/rs/cors](https://github.com/rs/cors) HTTP middleware for the Go
programming language.

## Installation

```
composer require flowpack/cors
```

(Refer to the [composer documentation](https://getcomposer.org/doc/) for more details)

The default settings enables CORS for all origins (`*`) in the Flow Development context. This is usually not what you
want in a production environment.

## Configuration

In your package or global `Settings.yaml` (
see [Flow framework Configuration](http://flowframework.readthedocs.io/en/stable/TheDefinitiveGuide/PartIII/Configuration.html)).

### Enable CORS in Production:

```
Flowpack:
  Cors:

    enabled: true
    
    allowedOrigins:
      - 'trusted-domain.tld'
```

### Add additional allowed headers (e.g. `Authorization`):

```
Flowpack:
  Cors:

    allowedHeaders:
      # defaults
      - 'Origin'
      - 'Accept'
      - 'Content-Type'
      # additional headers
      - 'Authorization'
```

Note: Make sure to set _all_ array values including the defaults (if you want to keep them) in the configuration because
the Flow configuration is merged with numeric keys which can lead to unwanted effects.

### Configuration reference

```
Flowpack:
  Cors:

    enabled: false

    # A list of origins a cross-domain request can be executed from
    # If the special * value is present in the list, all origins will be allowed.
    # An origin may contain a wildcard (*) to replace 0 or more characters (i.e.: http://*.domain.com).
    # Only one wildcard can be used per origin.
    #
    allowedOrigins:
      - '*'

    # A list of methods the client is allowed to use with cross-domain requests.
    #
    allowedMethods:
      - 'GET'
      - 'POST'

    # A list of non simple headers the client is allowed to use with cross-domain requests.
    #
    allowedHeaders:
      - 'Origin'
      - 'Accept'
      - 'Content-Type'

    # Indicates which headers are safe to expose to the API of a CORS API specification
    #
    exposedHeaders: []

    # Indicates whether the request can include user credentials like cookies, HTTP authentication or client side SSL certificates.
    #
    allowCredentials: false

    # Indicates how long (in seconds) the results of a preflight request can be cached. The default is 0 which stands for no max age.
    #
    maxAge: 0
```
