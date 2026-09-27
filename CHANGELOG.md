# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 5.3.2 are described by their release commits.

## 5.4.0 - 2026-09-27

### Features

- Surface client_id_metadata_document_supported on OauthMetadata ([`6b8f639`](https://github.com/vpndetection-io/sdk-go/commit/6b8f63930b095e112385b2ceb35fbbf26f7e5e1a))

## 5.3.4 - 2026-09-27

### Fixes

- Drop every trailing slash, and bound an overlong Retry-After ([`1dd18eb`](https://github.com/vpndetection-io/sdk-go/commit/1dd18eb86cbb7efc790a24ee07cdf8a9f2fb22df))
- End the poll's sleep at its deadline, and saturate a server's values ([`d615108`](https://github.com/vpndetection-io/sdk-go/commit/d6151088a7c3cfcb9857c1337a3c29a0ee1df3c3))

## 5.3.3 - 2026-09-26

### Fixes

- Fail DownloadBytes on a length no process can hold, never panic ([`aa4a546`](https://github.com/vpndetection-io/sdk-go/commit/aa4a54695c03f1bf77dc485a8994e21468a93024))

## 5.3.2 - 2026-09-25

### Fixes

- Share one request per address between concurrent misses ([`38df1c1`](https://github.com/vpndetection-io/sdk-go/commit/38df1c18b246a958003af73593f04440b8915f8f))
