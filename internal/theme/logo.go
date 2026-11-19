package theme

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg" // register JPEG decoding
	"image/png"
)

// Logo limits. The pixel bound is checked from the header before decoding,
// so a "decompression bomb" (a tiny file declaring a gigantic image) is
// refused without allocating memory for it.
const (
	maxLogoBytes  = 512 << 10
	maxLogoPixels = 1024 * 1024
)

// SanitizeLogo accepts a PNG or JPEG logo and returns a freshly encoded PNG.
//
// Re-encoding means the served bytes contain only pixels: metadata,
// trailing data and polyglot payloads (e.g. HTML or script appended to an
// image) are dropped. SVG and every other format are refused, because SVG
// is a document format that can carry script.
func SanitizeLogo(data []byte) ([]byte, error) {
	if len(data) > maxLogoBytes {
		return nil, errors.New("logo must be at most 512 KiB")
	}
	if !bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) && !bytes.HasPrefix(data, []byte{0xff, 0xd8, 0xff}) {
		return nil, errors.New("logo must be a PNG or JPEG image (SVG is not accepted because it can contain script)")
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("logo is not a valid image")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width*cfg.Height > maxLogoPixels || cfg.Width > 4096 || cfg.Height > 4096 {
		return nil, errors.New("logo dimensions must be at most 1 megapixel")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("logo is not a valid image")
	}
	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
