//! Favicon images: the format is told by the bytes, only ICO,
//! PNG, JPEG, GIF, WebP and BMP up to 1024 × 1024, re-encoded as a 64 × 64
//! PNG scaled like the client does it.

use std::io::Cursor;

use image::codecs::png::PngEncoder;
use image::imageops::{self, FilterType};
use image::{ExtendedColorType, ImageEncoder, ImageFormat, ImageReader, Limits, RgbaImage};

pub const SIZE: u32 = 64;
const MAX_SIDE: u32 = 1024;
/// Generous for a 1024 × 1024 RGBA image and the decoder's buffers.
const MAX_ALLOC: u64 = 16 * 1024 * 1024;

/// Size of the scaled image inside the 64 × 64 square: fitted with its
/// aspect ratio; smaller images only grow by a whole factor.
pub fn fit(width: u32, height: u32) -> (u32, u32) {
    let longest = width.max(height).max(1);
    if longest <= SIZE {
        let factor = SIZE / longest;
        return (width * factor, height * factor);
    }
    let scale = |side: u32| {
        ((u64::from(side) * u64::from(SIZE) + u64::from(longest) / 2) / u64::from(longest)).max(1)
            as u32
    };
    (scale(width), scale(height))
}

fn decode(bytes: &[u8]) -> Option<RgbaImage> {
    let format = image::guess_format(bytes).ok()?;
    if !matches!(
        format,
        ImageFormat::Ico
            | ImageFormat::Png
            | ImageFormat::Jpeg
            | ImageFormat::Gif
            | ImageFormat::WebP
            | ImageFormat::Bmp
    ) {
        return None;
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_ALLOC);
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    reader.limits(limits);
    let image = reader.decode().ok()?;
    if image.width() == 0 || image.height() == 0 {
        return None;
    }
    Some(image.to_rgba8())
}

/// The icon as a 64 × 64 PNG with a transparent border, or `None` if the
/// bytes are no allowed image.
pub fn icon(bytes: &[u8]) -> Option<Vec<u8>> {
    let image = decode(bytes)?;
    let (width, height) = fit(image.width(), image.height());
    let filter = if width >= image.width() {
        FilterType::Nearest
    } else {
        FilterType::Lanczos3
    };
    let scaled = imageops::resize(&image, width, height, filter);
    let mut canvas = RgbaImage::new(SIZE, SIZE);
    imageops::replace(
        &mut canvas,
        &scaled,
        i64::from((SIZE - width) / 2),
        i64::from((SIZE - height) / 2),
    );
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(canvas.as_raw(), SIZE, SIZE, ExtendedColorType::Rgba8)
        .ok()?;
    Some(png)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::codecs::bmp::BmpEncoder;
    use image::codecs::gif::{GifEncoder, Repeat};
    use image::codecs::ico::{IcoEncoder, IcoFrame};
    use image::codecs::jpeg::JpegEncoder;
    use image::codecs::webp::WebPEncoder;
    use image::{Delay, Frame, Rgba};

    fn checkerboard(width: u32, height: u32) -> RgbaImage {
        RgbaImage::from_fn(width, height, |x, y| {
            if (x + y) % 2 == 0 {
                Rgba([255, 0, 0, 255])
            } else {
                Rgba([0, 0, 255, 255])
            }
        })
    }

    fn png(image: &RgbaImage) -> Vec<u8> {
        let mut out = Vec::new();
        PngEncoder::new(&mut out)
            .write_image(
                image.as_raw(),
                image.width(),
                image.height(),
                ExtendedColorType::Rgba8,
            )
            .unwrap();
        out
    }

    fn decoded(bytes: &[u8]) -> RgbaImage {
        image::load_from_memory_with_format(bytes, ImageFormat::Png)
            .unwrap()
            .to_rgba8()
    }

    #[test]
    fn fits_like_the_client() {
        assert_eq!(fit(16, 16), (64, 64));
        assert_eq!(fit(48, 48), (48, 48));
        assert_eq!(fit(20, 10), (60, 30));
        assert_eq!(fit(64, 64), (64, 64));
        assert_eq!(fit(512, 256), (64, 32));
        assert_eq!(fit(1000, 3), (64, 1));
        assert_eq!(fit(100, 50), (64, 32));
        assert_eq!(fit(65, 64), (64, 63));
    }

    #[test]
    fn small_icons_grow_without_smoothing() {
        let out = decoded(&icon(&png(&checkerboard(16, 16))).unwrap());
        assert_eq!(out.dimensions(), (64, 64));
        for y in 0..64 {
            for x in 0..64 {
                let expected = if (x / 4 + y / 4) % 2 == 0 {
                    Rgba([255, 0, 0, 255])
                } else {
                    Rgba([0, 0, 255, 255])
                };
                assert_eq!(*out.get_pixel(x, y), expected, "{x},{y}");
            }
        }
    }

    #[test]
    fn keeps_a_transparent_border() {
        let out = decoded(&icon(&png(&checkerboard(48, 48))).unwrap());
        assert_eq!(out.get_pixel(7, 7)[3], 0);
        assert_eq!(*out.get_pixel(8, 8), Rgba([255, 0, 0, 255]));
        assert_eq!(*out.get_pixel(55, 55), Rgba([255, 0, 0, 255]));
        assert_eq!(out.get_pixel(56, 56)[3], 0);

        let wide =
            decoded(&icon(&png(&RgbaImage::from_pixel(512, 256, Rgba([9, 9, 9, 255])))).unwrap());
        assert_eq!(wide.get_pixel(32, 15)[3], 0);
        assert_eq!(wide.get_pixel(32, 16)[3], 255);
        assert_eq!(wide.get_pixel(32, 47)[3], 255);
        assert_eq!(wide.get_pixel(32, 48)[3], 0);
    }

    #[test]
    fn decodes_every_allowed_format() {
        let image = RgbaImage::from_pixel(32, 32, Rgba([10, 200, 30, 255]));
        let rgb = image::DynamicImage::ImageRgba8(image.clone()).to_rgb8();
        let mut jpeg = Vec::new();
        JpegEncoder::new(&mut jpeg).encode_image(&rgb).unwrap();
        let mut bmp = Vec::new();
        BmpEncoder::new(&mut bmp)
            .write_image(image.as_raw(), 32, 32, ExtendedColorType::Rgba8)
            .unwrap();
        let mut ico = Vec::new();
        IcoEncoder::new(&mut ico)
            .encode_images(&[
                IcoFrame::as_png(&RgbaImage::new(16, 16), 16, 16, ExtendedColorType::Rgba8)
                    .unwrap(),
                IcoFrame::as_png(image.as_raw(), 32, 32, ExtendedColorType::Rgba8).unwrap(),
            ])
            .unwrap();
        let mut gif = Vec::new();
        {
            let mut encoder = GifEncoder::new(&mut gif);
            encoder.set_repeat(Repeat::Infinite).unwrap();
            encoder
                .encode_frames([
                    Frame::from_parts(image.clone(), 0, 0, Delay::from_numer_denom_ms(100, 1)),
                    Frame::from_parts(
                        RgbaImage::from_pixel(32, 32, Rgba([0, 0, 0, 255])),
                        0,
                        0,
                        Delay::from_numer_denom_ms(100, 1),
                    ),
                ])
                .unwrap();
        }
        let mut webp = Vec::new();
        WebPEncoder::new_lossless(&mut webp)
            .encode(image.as_raw(), 32, 32, ExtendedColorType::Rgba8)
            .unwrap();
        for (name, bytes) in [
            ("png", png(&image)),
            ("jpeg", jpeg),
            ("bmp", bmp),
            ("ico", ico),
            ("gif", gif),
            ("webp", webp),
        ] {
            let out = decoded(&icon(&bytes).unwrap_or_else(|| panic!("{name}")));
            assert_eq!(out.dimensions(), (64, 64), "{name}");
            let pixel = out.get_pixel(32, 32);
            assert!(
                pixel[1] > 150 && pixel[0] < 60 && pixel[3] == 255,
                "{name}: {pixel:?}"
            );
        }
    }

    #[test]
    fn rejects_svg_other_formats_and_garbage() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"></svg>"#;
        assert_eq!(icon(svg), None);
        assert_eq!(icon(b"<html><body>not an image</body></html>"), None);
        assert_eq!(icon(b""), None);
        let mut truncated = png(&checkerboard(32, 32));
        truncated.truncate(40);
        assert_eq!(icon(&truncated), None);
        // TIFF is decodable in general, but not allowed here.
        assert_eq!(icon(b"II*\0\x08\0\0\0"), None);
    }

    #[test]
    fn rejects_images_beyond_1024_pixels() {
        let big = png(&RgbaImage::new(1025, 1));
        assert_eq!(icon(&big), None);
        let tall = png(&RgbaImage::new(1, 1025));
        assert_eq!(icon(&tall), None);
        let edge = png(&RgbaImage::new(1024, 1024));
        assert!(icon(&edge).is_some());
    }

    #[test]
    fn the_output_is_a_64_pixel_png() {
        let out = icon(&png(&checkerboard(100, 50))).unwrap();
        assert_eq!(&out[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&out[12..16], b"IHDR");
        assert_eq!(&out[16..24], &[0, 0, 0, 64, 0, 0, 0, 64]);
    }
}
