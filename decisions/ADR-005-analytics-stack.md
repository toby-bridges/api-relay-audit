# ADR-005: Analytics Stack

**Status:** Accepted  
**Date:** 2026-07-20

## Context

The project currently has a public GitHub Pages site, robots.txt, sitemap.xml, canonical URLs, hreflang metadata, and guide pages, but no configured search-performance or product-behavior measurement.

The tool runs locally and handles security-sensitive inputs. The measurement stack must not weaken the project's privacy promise.

## Decision

Use the following initial stack:

1. **Google Search Console** for search discovery, indexing, queries, pages, countries, and devices.
2. **A privacy-restricted website analytics implementation** for explicit custom events only. PostHog is the preferred learning environment, but production integration requires a project key and a separate implementation PR.
3. **Manual user research** for the core value event: successful audit completion and correct report understanding.
4. **Manual GEO measurement** using a fixed prompt set and documented review rules.

## Initial analytics restrictions

- No CLI telemetry.
- No session replay.
- No user identification.
- No broad autocapture.
- No sensitive values in event properties.
- Development and production traffic must be distinguishable.

## Consequences

Website events measure intent and navigation, not successful audit completion. The North Star remains partially observable until voluntary feedback and user research are available.

Analytics implementation is intentionally separated from this documentation and schema PR because credentials and verification tokens are not yet configured.
