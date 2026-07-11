package sources

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/betterleaks/betterleaks/logging"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/errgroup"
)

// OCIArtifact will parse an OCI artifact
// from a remote registry and yeild fragments for
// the contents of the layers and for image metadata
// such as the config and manifest attributes
type OCIArtifact struct {
	// Reference is the refernce to the image
	Reference name.Reference

	// Scan config
	MaxObjectSize   int64
	Workers         int
	ShouldSkip      SkipFunc
	MaxArchiveDepth int
}

// Fragments dispatches to single-bucket or enumerate-mode scanning based on
// the parsed URL.
func (o *OCIArtifact) Fragments(ctx context.Context, yield FragmentsFunc) error {
	maxSize := o.MaxObjectSize
	if maxSize <= 0 {
		maxSize = s3DefaultMaxObjectSize
	}
	workers := o.Workers
	if workers <= 0 {
		workers = s3DefaultWorkers
	}

	ociAttrs := map[string]string{
		AttrOCIRegistry:   o.Reference.Context().RegistryStr(),
		AttrOCIRepository: o.Reference.Context().RepositoryStr(),
		AttrOCITag:        o.Reference.Identifier(),
	}
	if o.ShouldSkip != nil && o.ShouldSkip(ociAttrs) {
		logging.Info().Str("reference", o.Reference.String()).Msg("skipping artifact: filtered by prefilter")
		return nil
	}

	logging.Info().
		Str("reference", o.Reference.String()).
		Msg("starting OCI artifact scan")

	start := time.Now()
	var (
		listedCount  int // every object returned by ListObjectsV2
		scannedCount int // objects fully fetched + processed without error
		mu           sync.Mutex
	)

	img, err := remote.Image(o.Reference, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		logging.Err(err).Str("reference", o.Reference.String()).Msg("unable to access remote image")
		return fmt.Errorf("remote image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		logging.Err(err).Str("reference", o.Reference.String()).Msg("unable to list image layers")
		return fmt.Errorf("remote image: %w", err)
	}

	for _, l := range layers {
		err := o.fragmentLayer(ctx, l, yield)
		if err != nil {
			logging.Err(err).Str("reference", o.Reference.String()).Msg("unable to fragment layer, skipping")
			continue
		}
	}

	logging.Info().
		Str("reference", o.Reference.String()).
		Int("objects_listed", listedCount).
		Int("objects_scanned", scannedCount).
		Str("duration", time.Since(start).Round(time.Millisecond).String()).
		Msg("oci scan complete")
	return nil
}

func (o *OCIArtifact) fragmentLayer(ctx context.Context, l v1.Layer, yield FragmentsFunc) error {
	digest, _ := l.Digest() // ignore error, just for logging

	rc, err := l.Uncompressed()
	if err != nil {
		logging.Err(err).
			Str("reference", o.Reference.String()).
			Str("layerdigest", digest.String()).
			Msg("unable to retrieve uncompressed layer")
		return err
	}
	defer rc.Close()

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(workers)

	tr := tar.NewReader(rc)
	for {
		header, err := tr.Next()
		switch {
		case err == io.EOF:
			break
		case err != nil:
			return fmt.Errorf("error while reading tar: %s", err)
		case header == nil:
			continue
		}

		g.Go(func() error {
			if err := o.scanLayerFile(ctx, tr, header, yield); err != nil {
				logging.Error().Err(err).
					Str("file", header.Name).
					Str("layerdigest", digest.String()).
					Msg("could not scan layer file")
				return nil
			}
			mu.Lock()
			scannedCount++
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}

func (o *OCIArtifact) scanLayerFile(ctx context.Context, tr *tar.Reader, header *tar.Header, yield FragmentsFunc) error {
	objCtx, cancel := context.WithTimeout(ctx, ociPerObjectTimeout)
	defer cancel()

	body, err := s3GetObject(objCtx, client, target, s.creds, obj.Key)
	if err != nil {
		return err
	}
	defer body.Close()

	stampedYield := s.wrapYieldWithAttrs(attrs, yield)
	file := &File{
		Content:         body,
		Path:            header.Name,
		MaxArchiveDepth: s.MaxArchiveDepth,
		ShouldSkip:      s.ShouldSkip,
	}
	return file.Fragments(objCtx, stampedYield)
}

type OCIArchive struct {
	Reference name.Reference
	Path      string
}
