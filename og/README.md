# OpenGraph preview images

Each repository page links to an `og.png` preview image at its bucket root.
The five HTML templates in this directory are the sources of the images.
Each template follows the hero design of its repository page.
The rendered images are in `src/haberdasher/og/`, and `just publish` reads them from the package.

## Regenerate the images

1. Run `./fetch-fonts.sh` to download the fonts from pinned jsDelivr URLs into `fonts/`.
   Git ignores `fonts/`, so the repository does not hold the font files.
2. Run `./render.sh` to render all five images, or name the formats, for example `./render.sh apt rpm`.

The render script uses headless Firefox and `oxipng` from nixpkgs.
It writes each image to `src/haberdasher/og/<format>.png`.
It fails if an image is not exactly 1200 × 630 pixels or is 300 KB or larger.
