package vpndetection

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/vpndetection-io/sdk-go/internal/api"
)

// Database is the licensed dataset downloads. Access is granted by contract
// rather than self-serve, and needs a key carrying the db.download scope.
type Database struct {
	api      *api.ClientWithResponses
	transfer *http.Client
	retries  int
}

// List is the dataset families your organization is licensed to download. A
// license covers a family, while a download names one of its versions, so the
// ids Download and Checksums take come from LicensedDataset.Versions.
func (d *Database) List(ctx context.Context) ([]LicensedDataset, error) {
	return withRetry(ctx, d.retries, func() ([]LicensedDataset, error) {
		res, err := d.api.ListDatabasesWithResponse(ctx)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200.Datasets, nil
	})
}

// Metadata is what is inside one dataset: schema, samples, row count and sizes.
// It carries `updated` and `entries` without downloading anything, so poll it
// to decide whether today's build is worth fetching.
func (d *Database) Metadata(ctx context.Context, id string) (*DatasetMetadata, error) {
	return withRetry(ctx, d.retries, func() (*DatasetMetadata, error) {
		res, err := d.api.DatabaseMetadataWithResponse(ctx, &api.DatabaseMetadataParams{ID: id})
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200, nil
	})
}

// Checksums are the digests of one published file, for verifying a download.
func (d *Database) Checksums(ctx context.Context, id string, format Format) (*Checksums, error) {
	return withRetry(ctx, d.retries, func() (*Checksums, error) {
		res, err := d.api.DatabaseChecksumWithResponse(ctx, &api.DatabaseChecksumParams{
			ID:     id,
			Format: api.DatabaseChecksumParamsFormat(format),
		})
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		sums := res.JSON200.Checksums
		return &Checksums{
			MD5:    deref(sums.Md5),
			SHA1:   deref(sums.Sha1),
			SHA256: deref(sums.Sha256),
			SHA512: deref(sums.Sha512),
		}, nil
	})
}

// Downloads is your organization's recent download attempts, newest first. A
// limit of zero or less takes the API's own default.
func (d *Database) Downloads(ctx context.Context, limit int) ([]Download, error) {
	return withRetry(ctx, d.retries, func() ([]Download, error) {
		params := &api.ListDownloadsParams{}
		if limit > 0 {
			params.Limit = &limit
		}
		res, err := d.api.ListDownloadsWithResponse(ctx, params)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusOK || res.JSON200 == nil {
			return nil, errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		return res.JSON200.Downloads, nil
	})
}

// DownloadURL is the time-limited URL for one dataset file.
//
// The API answers 302 to object storage. The URL is returned rather than the
// bytes so the caller decides how to transfer a file that routinely runs to
// gigabytes; the link authorizes the START of a transfer, so one already
// running is not interrupted when it lapses.
func (d *Database) DownloadURL(ctx context.Context, id string, format Format) (string, error) {
	ctx = withoutRedirects(ctx)
	return withRetry(ctx, d.retries, func() (string, error) {
		res, err := d.api.DownloadDatabaseWithResponse(ctx, &api.DownloadDatabaseParams{
			ID:     id,
			Format: api.DownloadDatabaseParamsFormat(format),
		})
		if err != nil {
			return "", errorFromTransport(err)
		}
		if res.StatusCode() != http.StatusFound {
			return "", errorFromResponse(res.StatusCode(), res.HTTPResponse.Header, res.Body)
		}
		if res.Headers302 == nil || res.Headers302.Location == nil {
			return "", &Error{
				Kind:       KindServerError,
				Message:    "redirect carried no Location header",
				StatusCode: res.StatusCode(),
			}
		}
		return *res.Headers302.Location, nil
	})
}

// Download streams one dataset file into dst and returns the bytes written.
//
// Nothing beyond a single chunk is ever held in memory, whatever the dataset
// weighs. The transfer takes its deadline from ctx rather than from the HTTP
// client's Timeout, which would cap the whole body: 30 seconds is a sane bound
// on a lookup and the wrong one on a gigabyte.
//
// A failure DURING the transfer is returned as it happened rather than wrapped
// in an *Error: a reset socket and a full disk are different problems, and only
// one of them is ours.
func (d *Database) Download(
	ctx context.Context, id string, format Format, dst io.Writer,
) (int64, error) {
	res, err := d.fetchFile(ctx, id, format)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	return io.Copy(dst, res.Body)
}

// DownloadFile writes one dataset file to path and returns the bytes written.
//
// The bytes land in a neighboring .part file that is renamed on completion, so
// a transfer that dies half way leaves no truncated file that reads as a whole
// dataset. Otherwise identical to Download.
func (d *Database) DownloadFile(
	ctx context.Context, id string, format Format, path string,
) (int64, error) {
	res, err := d.fetchFile(ctx, id, format)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	partial := path + ".part"
	file, err := os.Create(partial)
	if err != nil {
		return 0, err
	}
	written, err := io.Copy(file, res.Body)
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(partial, path)
	}
	if err != nil {
		_ = os.Remove(partial)
		return written, err
	}
	return written, nil
}

// DownloadBytes downloads one dataset file and hands back its bytes.
//
// This holds the ENTIRE file in memory, and the catalog spans five orders of
// magnitude, from cdn_ip_v1 at 10 KB to resproxy_ip_90d_v1 at 1.79 GB, so reach
// for it at the small end and use Download or DownloadFile for anything you
// have not measured.
func (d *Database) DownloadBytes(ctx context.Context, id string, format Format) ([]byte, error) {
	res, err := d.fetchFile(ctx, id, format)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.ContentLength < 0 {
		return io.ReadAll(res.Body)
	}
	// Allocated once from the declared length. io.ReadAll grows by doubling, so
	// on a large dataset the final grow alone costs twice the file.
	buf := make([]byte, res.ContentLength)
	if _, err := io.ReadFull(res.Body, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// The 302 is followed as a SECOND, unauthenticated request rather than by
// loosening the redirect guard: the presigned URL authorizes itself, so
// forwarding the API key would hand a credential to a host with no business
// holding it. The key rides a request editor on the generated client, which
// this request does not go through.
func (d *Database) fetchFile(
	ctx context.Context, id string, format Format,
) (*http.Response, error) {
	url, err := d.DownloadURL(ctx, id, format)
	if err != nil {
		return nil, err
	}
	return withRetry(ctx, d.retries, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		res, err := d.transfer.Do(req)
		if err != nil {
			return nil, errorFromTransport(err)
		}
		if res.StatusCode != http.StatusOK {
			// Left unread: the status is what separates a lapsed link from a
			// refused one, and nothing bounds the size of an error body.
			res.Body.Close()
			failure := errorFromResponse(res.StatusCode, res.Header, nil)
			failure.Message = fmt.Sprintf(
				"object storage refused the download link with status %d", res.StatusCode)
			return nil, failure
		}
		return res, nil
	})
}

// Format is a format a dataset is published in. Not every dataset is built in
// every format: the _provider catalogs are keyed by provider id rather than
// by IP range, so no MMDB exists for them.
type Format string

const (
	FormatCSVGZ Format = "csvgz"
	FormatMMDB  Format = "mmdb"
)

// Checksums of one published dataset file. A digest the exporter did not write
// is an empty string.
type Checksums struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

// The dataset shapes, re-exported so a consumer never has to name an internal
// package.
type (
	LicensedDataset       = api.LicensedDataset
	DatasetFormatSize     = api.DatasetFormatSize
	DatasetMetadata       = api.DatasetMetadata
	DatasetMetadataColumn = api.DatasetMetadataColumn
	Download              = api.Download
	// LicensedVersion is one published version of a licensed family. Its ID is
	// what the download and checksum calls take.
	LicensedVersion = api.LicensedVersion
	// LicenseType is what a license permits you to do with the data.
	LicenseType = api.LicensedDatasetLicenseType
	// Standing is where a license stands: live, lapsed, or never bought.
	Standing = api.LicensedDatasetStanding
	// SampleFormat is a format an evaluation sample is published in.
	SampleFormat = api.LicensedVersionSampleFormats
	// DownloadOutcome is how one download attempt ended.
	DownloadOutcome = api.DownloadOutcome
)

const (
	LicenseTypeEvaluation   = api.Evaluation
	LicenseTypeStandard     = api.Standard
	LicenseTypeRedistribute = api.Redistribute
)

const (
	StandingExpired    = api.LicensedDatasetStandingExpired
	StandingLicensed   = api.LicensedDatasetStandingLicensed
	StandingUnlicensed = api.LicensedDatasetStandingUnlicensed
)

const (
	DownloadOutcomeOK           = api.DownloadOutcomeOk
	DownloadOutcomeUnauthorized = api.DownloadOutcomeUnauthorized
	DownloadOutcomeDenied       = api.DownloadOutcomeDenied
	DownloadOutcomeExpired      = api.DownloadOutcomeExpired
	DownloadOutcomeUnknown      = api.DownloadOutcomeUnknown
	DownloadOutcomeUnavailable  = api.DownloadOutcomeUnavailable
)
