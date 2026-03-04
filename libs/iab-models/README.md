# IAB Models Library

Shared IAB TCF 2.2 data models and utilities for PCM.

## Overview

This library provides:
- IAB TCF 2.2 data models (purposes, vendors, consent records)
- Shared enums and constants
- Utility classes for working with TC Strings
- Common validation logic

## Dependencies

- Spring Data JPA for entity annotations
- IAB TCF Java library (decoder/encoder)
- Jackson for JSON processing
- jqwik for property-based testing

## Usage

Add this dependency to your service:

```xml
<dependency>
    <groupId>dev.vibe-afrika</groupId>
    <artifactId>pcm-iab-models</artifactId>
    <version>${project.version}</version>
</dependency>
```

## Build

```bash
mvn clean install
```
