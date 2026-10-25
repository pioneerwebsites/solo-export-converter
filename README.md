# Solo Export Converter

A static, browser-only utility for turning Solo AI Website Builder exports into separate Cloudflare Pages ZIP deployments. There is no build step, server application, database or runtime dependency other than Bootstrap 5.3.6, which is included locally.

This tool was one-shot using ChatGPT on 2026-10-25.  It took around 15 minutes to generate.  The prompt was as follows:

> The project is to one-shot a simple web interface to convert an export from [Solo AI Website Builder](soloist.ai) into a static web bundle that can be imported into cloudflare pages or cloudflare drop.  The interface should use bootstrap styling and this is the only permitted external dependency.  The site should be totally static and possible to host on cloudflare pages itself.  There should be space on the page to write some tips and instructions which can be placeholders for now.  The flow should be as follows:
> 
> 1. Allow drag and drop or browse uploading of a zip file.
> 2. Extract the zip file, each site in the export is a sub-directory of the zip.
> 3. Remove the `contacts.csv` file from the directory and offer it as a separate download.
> 4. Import the `images.csv` file which has the header format `Page,Section,Section title,Location,Image URL,Source,Attribution` and an example row is `...redacted...`
> 5. For each image in the CSV, download it from the URL (perhaps using XHR and displaying it as an icon in the interface)
> 6. Display an option to create a new zip file for each site in the original export
> 7. When the user clicks the download button on that zip file, copy the remaining `html` files and the `assets` folder from original subdirectory of the export, as well as all the downloaded images for that site into an `img` subdirectory, the images should be named after a filename escaped version of the `Location` column. Then find and replace those references to the images in the HTML files referenced in the `Page` column (`/` -> `index.html`, `page-one` -> `page-one.html`, etc.) with the remote images originally in the HTML source.
> 8. Trigger the new zip to download.

## Deploy the converter

Upload a ZIP of this repo to Cloudflare **Workers & Pages → Create application → Drag and drop**. The ZIP has `index.html` at its root; no unzipping is necessary for Cloudflare dashboard direct upload. You can also extract the ZIP and host the files on any HTTPS static host. The `_headers` file configures security headers on Cloudflare Pages.

## Convert an export

1. In Solo, download your website data, which should include folders containing HTML, an `assets` folder and `images.csv`.
2. Drag the export ZIP into the converter or select it in the browser.
3. Review image statuses and previews. Images are fetched directly by the browser from the URLs in the CSV. If a source blocks CORS, right-click **Open original image → Save link as...** and save the image to your computer, then use **Add images manually** to upload it. The selected local filename should match the original image URL's basename, or a generated Location-based filename shown in the image details.
4. Download each site's ZIP. The site's HTML and `assets` folder are preserved; downloaded raster images are saved to `img/`, and image URL occurrences in the HTML file specified by the CSV's `Page` column are replaced with the correct local relative path.
5. Download any `contacts.csv` files separately and store them securely. Contacts CSV files and images.csv are excluded from site ZIPs.
6. EASY: Use [Cloudflare Drop](https://www.cloudflare.com/drop/) to walk you through the process. MANUAL: In Cloudflare Workers & Pages, create a Pages project using **Drag and drop**, then upload each generated site ZIP. Configure custom domains as required.  Alternatively 

## Supported formats and constraints

- Input ZIP: ordinary standard ZIP (stored or DEFLATE compressed entries), including UTF-8 filenames. Encrypted, ZIP64 and multi-volume ZIPs are not supported.
- CSV: parses quoted commas, escaped quotation marks, CRLF and multiline values. Must contain `Page`, `Location` and `Image URL` among its columns.
- CSV location: supports one `images.csv` per site, or a shared root-level file. For shared images.csv across multiple sites, pages are associated by matching the actual image URL in the relevant HTML. Unmatched rows are reported.
- Page mapping: `/` to `index.html`; `/page-one` to `page-one.html`; `/section/page` to `section/page.html` or `section/page/index.html` if present. Relative image links account for HTML files in nested folders.
- Image types: JPEG, PNG, WebP, GIF, AVIF, BMP. SVG and other potentially active/non-image files are deliberately rejected rather than published without sanitisation.
- Export ZIP uses uncompressed ZIP entries (STORE). It may be larger than the original archive but is valid for Cloudflare upload.
- Practical safeguards: 600 MB input ZIP, 1 GB declared uncompressed content, 256 MB per archive entry, 25 MiB per downloaded image, 15,000 ZIP entries. Large archives can still exceed the browser's available memory.
- Cloudflare Pages dashboard drag-and-drop currently limits each deployment to **1,000 files** and **25 MiB per file**. The converter warns about these limits at export. Wrangler supports more files but cannot directly accept a ZIP; unzip first and deploy its folder.

## Security and privacy

- Original ZIPs, extracted CSVs, HTML and downloaded images are processed in browser memory. No application backend receives them.
- Image requests **do** go to the source URL host from images.csv. They reveal the visitor's IP address to that host, as any normal download would. XHR requests do not opt into sending cross-origin credentials. The app uses a no-referrer policy.
- The converter validates ZIP filenames and rejects path traversal, excessive sizes, encrypted entries and malformed CRCs. It does not render the imported HTML or trust it as UI markup.
- The source website's original HTML and assets may contain scripts, tracking, embeds, forms and external dependencies. Inspect each generated website before making it public. Original forms will not submit on a static host without a replacement backend/service.
- `contacts.csv` can contain personal information. Keep it private, control access and retention, and do not upload it to Cloudflare Pages.
- `_headers` applies a restrictive Content Security Policy and clickjacking, MIME, permissions and referrer protections **to the converter**, not to websites generated from untrusted HTML. This avoids silently breaking scripts and embeds in those exported sites. Apply site-specific protections after auditing each site.

## Implementation files

- `index.html`: interface, status regions and placeholder help content
- `style.css`: presentation and responsive layouts
- `app.js`: browser-only ZIP reader/writer, CSV parser, image handling and export
- `vendor/bootstrap.min.css`: Bootstrap 5.3.6 styling
- `vendor/BOOTSTRAP-LICENSE.txt`: Bootstrap licence
- `_headers`: security response headers for Cloudflare Pages

## Warranty

No warranty, express or implied.  Use at your own risk.  See `LICENSE` for full details.

