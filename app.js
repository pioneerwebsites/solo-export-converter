'use strict';

// Browser-only Solo export converter. No runtime libraries apart from bundled Bootstrap CSS.
(() => {
  const MAX_ARCHIVE_BYTES = 600 * 1024 * 1024;
  const MAX_ENTRY_BYTES = 256 * 1024 * 1024;
  const MAX_TOTAL_UNPACKED = 1024 * 1024 * 1024;
  const MAX_IMAGE_BYTES = 25 * 1024 * 1024;
  const CLOUDFLARE_ASSET_LIMIT = 25 * 1024 * 1024;
  const CLOUDFLARE_DRAG_DROP_FILES_LIMIT = 1000;
  const MAX_ENTRIES = 15000;
  const CONCURRENCY = 4;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8');
  const $ = id => document.getElementById(id);

  const state = {
    generation: 0, zip: null, sites: [], globalContacts: [], warnings: [], images: new Map(),
    activeRequests: new Set(), objectUrls: [], processing: false
  };

  const crcTable = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crcTable[n] = c >>> 0;
  }
  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) crc = crcTable[(crc ^ bytes[i]) & 255] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
  }
  function uint16(view, at) { return view.getUint16(at, true); }
  function uint32(view, at) { return view.getUint32(at, true); }
  function safePath(raw) {
    if (/^(?:\/|\\|[A-Za-z]:)/.test(raw) || raw.includes('\0')) throw new Error('Unsafe ZIP path rejected.');
    const parts = raw.replaceAll('\\', '/').split('/').filter(p => p && p !== '.');
    if (parts.some(p => p === '..')) throw new Error('Unsafe ZIP traversal path rejected.');
    return parts.join('/');
  }
  function normalPath(path) { return safePath(path); }
  function ownName(path) { return path.slice(path.lastIndexOf('/') + 1); }
  function dirname(path) { const i = path.lastIndexOf('/'); return i < 0 ? '' : path.slice(0, i); }
  function belongs(path, root) { return root === '' || path.startsWith(root + '/'); }
  function relativeTo(path, root) { return root ? path.slice(root.length + 1) : path; }
  function makeElement(tag, cls, value) {
    const el = document.createElement(tag);
    if (cls) el.className = cls;
    if (value !== undefined) el.textContent = value;
    return el;
  }
  function showMessage(message, kind = 'danger') {
    const box = $('message'); box.textContent = message;
    box.className = `alert alert-${kind} mt-3`;
  }
  function clearMessage() { $('message').classList.add('d-none'); $('message').textContent = ''; }
  function slug(input) {
    return String(input || 'image').normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
      .toLowerCase().replace(/&/g, ' and ').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')
      .slice(0, 90) || 'image';
  }
  function filenameForSite(site) {
    return (site.outputLabel || slug(site.label === 'Website' ? 'solo-website' : site.label)) + '-static.zip';
  }
  function formatSize(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB']; let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(i ? 1 : 0)} ${units[i]}`;
  }

  // Reads ZIP central directory and standard STORE/DEFLATE entries using native browser APIs.
  // Explicit limits and path validation prevent most malformed ZIP and decompression-bomb cases.
  async function openZip(file) {
    if (file.size > MAX_ARCHIVE_BYTES) throw new Error('ZIP exceeds the 600 MB safety limit.');
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer), view = new DataView(buffer);
    if (bytes.length < 22) throw new Error('This file is not a valid ZIP archive.');
    let eocd = -1;
    for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
      if (uint32(view, i) === 0x06054b50 && i + 22 + uint16(view, i + 20) === bytes.length) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('ZIP central directory not found, or trailing content is unsupported.');
    if (uint16(view, eocd + 4) !== 0 || uint16(view, eocd + 6) !== 0) throw new Error('Multi-disk ZIP files are unsupported.');
    const count = uint16(view, eocd + 10), cdSize = uint32(view, eocd + 12), cdOffset = uint32(view, eocd + 16);
    if (count === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) throw new Error('ZIP64 exports are unsupported.');
    if (count > MAX_ENTRIES) throw new Error('ZIP contains too many files.');
    if (cdOffset + cdSize > eocd) throw new Error('Invalid ZIP central directory.');
    const entries = new Map();
    let p = cdOffset, totalUnpacked = 0;
    for (let i = 0; i < count; i++) {
      if (p + 46 > cdOffset + cdSize || uint32(view, p) !== 0x02014b50) throw new Error('Damaged ZIP central directory.');
      const flags = uint16(view, p + 8), method = uint16(view, p + 10);
      const crc = uint32(view, p + 16), compSize = uint32(view, p + 20), size = uint32(view, p + 24);
      const nameLen = uint16(view, p + 28), extraLen = uint16(view, p + 30), commentLen = uint16(view, p + 32);
      const localOffset = uint32(view, p + 42), next = p + 46 + nameLen + extraLen + commentLen;
      if (next > cdOffset + cdSize) throw new Error('Truncated ZIP entry.');
      if (flags & 1 || flags & 0x40) throw new Error('Encrypted ZIP entries are not supported.');
      if (method !== 0 && method !== 8) throw new Error(`ZIP compression method ${method} is unsupported.`);
      if (compSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) throw new Error('ZIP64 entries are unsupported.');
      if (size > MAX_ENTRY_BYTES) throw new Error('ZIP contains an oversized file.');
      totalUnpacked += size;
      if (totalUnpacked > MAX_TOTAL_UNPACKED) throw new Error('Uncompressed ZIP size exceeds 1 GB safety limit.');
      const nameBytes = bytes.subarray(p + 46, p + 46 + nameLen);
      const name = normalPath(decoder.decode(nameBytes));
      const isDir = nameBytes[nameBytes.length - 1] === 47 || nameBytes[nameBytes.length - 1] === 92;
      if (name && !isDir) {
        if (entries.has(name)) throw new Error(`Duplicate ZIP path rejected: ${name}`);
        if (localOffset + 30 > bytes.length || uint32(view, localOffset) !== 0x04034b50) throw new Error('Invalid ZIP local header.');
        const localMethod = uint16(view, localOffset + 8);
        if (localMethod !== method) throw new Error('Inconsistent ZIP compression information.');
        const dataOffset = localOffset + 30 + uint16(view, localOffset + 26) + uint16(view, localOffset + 28);
        if (dataOffset + compSize > cdOffset) throw new Error('Invalid ZIP compressed file boundaries.');
        entries.set(name, { name, size, compSize, method, crc, dataOffset });
      }
      p = next;
    }
    if (p !== cdOffset + cdSize) throw new Error('ZIP directory length mismatch.');
    return {
      entries,
      async read(entry) {
        const compressed = bytes.subarray(entry.dataOffset, entry.dataOffset + entry.compSize);
        let data;
        if (entry.method === 0) data = compressed;
        else {
          if (typeof DecompressionStream === 'undefined') throw new Error('Your browser does not support ZIP decompression.');
          let decompressor;
          try { decompressor = new DecompressionStream('deflate-raw'); }
          catch { throw new Error('This browser cannot decompress standard ZIP entries. Please use a current browser.'); }
          const reader = new Blob([compressed]).stream().pipeThrough(decompressor).getReader();
          const chunks = []; let total = 0;
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              total += value.length;
              if (total > MAX_ENTRY_BYTES || total > entry.size) throw new Error('ZIP entry expanded beyond its declared size.');
              chunks.push(value);
            }
          } catch (error) { await reader.cancel().catch(() => {}); throw error; }
          data = new Uint8Array(total);
          let at = 0;
          for (const chunk of chunks) { data.set(chunk, at); at += chunk.length; }
        }
        if (data.length !== entry.size || crc32(data) !== entry.crc) throw new Error(`ZIP entry failed integrity check: ${entry.name}`);
        return data;
      },
      async readText(entry) { return decoder.decode(await this.read(entry)); }
    };
  }

  // ZIP output uses STORE rather than recompression. This avoids dependencies and saves CPU.
  async function makeZip(files) {
    if (files.length > 65535) throw new Error('Too many output files for a standard ZIP.');
    const chunks = [], central = []; let offset = 0, cdLength = 0;
    const now = new Date();
    const dosDate = ((Math.max(1980, now.getFullYear()) - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
    const dosTime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
    for (const file of files) {
      const name = safePath(file.name);
      if (!name || name.startsWith('../')) throw new Error('Unsafe output ZIP path.');
      const fileName = encoder.encode(name), data = file.data;
      if (fileName.length > 65535) throw new Error('Output path is too long.');
      if (data.length >= 0xffffffff || offset + 30 + fileName.length + data.length >= 0xffffffff) throw new Error('ZIP would exceed 4 GB limit.');
      const crc = crc32(data);
      const local = new Uint8Array(30), l = new DataView(local.buffer);
      l.setUint32(0, 0x04034b50, true); l.setUint16(4, 20, true); l.setUint16(6, 0x0800, true);
      l.setUint16(8, 0, true); l.setUint16(10, dosTime, true); l.setUint16(12, dosDate, true);
      l.setUint32(14, crc, true); l.setUint32(18, data.length, true); l.setUint32(22, data.length, true);
      l.setUint16(26, fileName.length, true);
      chunks.push(local, fileName, data);
      const record = new Uint8Array(46), c = new DataView(record.buffer);
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true);
      c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true);
      c.setUint16(12, dosTime, true); c.setUint16(14, dosDate, true);
      c.setUint32(16, crc, true); c.setUint32(20, data.length, true); c.setUint32(24, data.length, true);
      c.setUint16(28, fileName.length, true); c.setUint32(42, offset, true);
      central.push(record, fileName); cdLength += 46 + fileName.length;
      offset += local.length + fileName.length + data.length;
    }
    const end = new Uint8Array(22), e = new DataView(end.buffer);
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true);
    e.setUint32(12, cdLength, true); e.setUint32(16, offset, true);
    return new Blob([...chunks, ...central, end], { type: 'application/zip' });
  }

  function parseCsv(text) {
    text = text.replace(/^\ufeff/, '');
    const rows = []; let row = [], field = '', inQuote = false;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      if (inQuote) {
        if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
        else if (ch === '"') inQuote = false;
        else field += ch;
      } else if (ch === '"' && !field.length) inQuote = true;
      else if (ch === ',') { row.push(field); field = ''; }
      else if (ch === '\n' || ch === '\r') {
        row.push(field); field = '';
        if (row.some(v => v.trim())) rows.push(row);
        row = [];
        if (ch === '\r' && text[i + 1] === '\n') i++;
      } else field += ch;
    }
    if (inQuote) throw new Error('Malformed CSV: an unclosed quoted field was found.');
    row.push(field);
    if (row.some(v => v.trim())) rows.push(row);
    if (!rows.length) return [];
    const headers = rows.shift().map(h => h.trim().toLowerCase());
    for (const required of ['page', 'location', 'image url']) {
      if (!headers.includes(required)) throw new Error(`images.csv is missing required column: ${required}`);
    }
    return rows.map((cells, n) => {
      const obj = { sourceRow: n + 2 };
      headers.forEach((h, i) => { obj[h] = cells[i] || ''; });
      return obj;
    }).filter(row => row['image url'].trim());
  }

  function htmlFileForPage(site, page) {
    let pathname;
    try { pathname = new URL(page, 'https://site.invalid/').pathname; }
    catch { return null; }
    if (/\.{2}|\\|\0/.test(pathname) || /%2f|%5c|%2e/i.test(pathname)) return null;
    let relative = decodeURIComponent(pathname).replace(/^\/+/, '');
    const siteDir = site.root.split('/').at(-1);
    if (siteDir && relative.startsWith(siteDir + '/')) relative = relative.slice(siteDir.length + 1);
    if (relative === siteDir) relative = '';
    const possibilities = relative === '' ? ['index.html'] : relative.endsWith('/')
      ? [relative + 'index.html', relative.slice(0, -1) + '.html']
      : relative.endsWith('.html') ? [relative] : [relative + '.html', relative + '/index.html'];
    return possibilities.find(name => site.htmlMap.has(name)) || null;
  }
  function urlVariants(url) {
    return [...new Set([url, url.replaceAll('&', '&amp;'), url.replaceAll('/', '\\/'),
      url.replaceAll('&', '&#38;'), url.replaceAll('&', '&#x26;')])];
  }
  function htmlContains(html, url) { return urlVariants(url).some(v => html.includes(v)); }
  function replaceUrl(html, url, local) {
    let matches = 0;
    for (const remote of urlVariants(url)) {
      if (!html.includes(remote)) continue;
      const pieces = html.split(remote);
      matches += pieces.length - 1;
      html = pieces.join(local);
    }
    return { html, matches };
  }
  function validateImageUrl(url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) return false;
      const host = parsed.hostname.toLowerCase();
      if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') ||
          /^(127\.|10\.|192\.168\.|169\.254\.|0\.|172\.(1[6-9]|2\d|3[01])\.|\[|::1)/.test(host)) return false;
      return true;
    } catch { return false; }
  }
  function imageFormat(bytes) {
    if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
    if (bytes.length >= 8 && bytes[0] === 137 && bytes[1] === 80 && bytes[2] === 78 && bytes[3] === 71 && bytes[4] === 13) return { ext: 'png', mime: 'image/png' };
    if (bytes.length >= 6 && decoder.decode(bytes.subarray(0, 3)) === 'GIF') return { ext: 'gif', mime: 'image/gif' };
    if (bytes.length >= 12 && decoder.decode(bytes.subarray(0, 4)) === 'RIFF' && decoder.decode(bytes.subarray(8, 12)) === 'WEBP') return { ext: 'webp', mime: 'image/webp' };
    if (bytes.length >= 12 && decoder.decode(bytes.subarray(4, 8)) === 'ftyp' && /^(?:avif|avis)$/.test(decoder.decode(bytes.subarray(8, 12)))) return { ext: 'avif', mime: 'image/avif' };
    if (bytes.length >= 2 && bytes[0] === 0x42 && bytes[1] === 0x4d) return { ext: 'bmp', mime: 'image/bmp' };
    return null; // Intentionally reject active SVG and non-image responses.
  }

  function releaseSession() {
    state.generation++;
    for (const req of state.activeRequests) req.abort();
    state.activeRequests.clear();
    for (const url of state.objectUrls) URL.revokeObjectURL(url);
    state.objectUrls.length = 0;
    state.zip = null; state.sites = []; state.globalContacts = []; state.images.clear(); state.warnings = [];
    state.processing = false;
    $('site-list').replaceChildren(); $('global-contacts').replaceChildren();
    $('results').classList.add('d-none'); $('allow-incomplete').checked = false;
  }

  async function inspectArchive(file) {
    releaseSession(); clearMessage();
    const current = state.generation;
    state.processing = true;
    const browseButton = $('browse-btn'); browseButton.disabled = true;
    showMessage('Reading ZIP and checking its contents…', 'info');
    try {
      state.zip = await openZip(file);
      if (current !== state.generation) return;
      const all = [...state.zip.entries.values()];
      const html = all.filter(e => /\.html?$/i.test(e.name) && !e.name.includes('__MACOSX/') && !e.name.split('/').includes('assets'));
      if (!html.length) throw new Error('No HTML files were found in this ZIP.');
      let roots = html.filter(e => ownName(e.name).toLowerCase() === 'index.html').map(e => dirname(e.name));
      if (!roots.length) roots = [...new Set(html.map(e => dirname(e.name)))];
      roots = [...new Set(roots)].sort((a, b) => a.length - b.length);
      const chosen = roots.filter(root => !roots.some(parent => parent !== root && belongs(root, parent)));
      state.sites = chosen.map(root => {
        const site = { root, label: root ? ownName(root) : 'Website', htmlMap: new Map(), assets: [], contacts: [], rows: [], warnings: [], ui: null, building: false };
        for (const entry of all) {
          if (!belongs(entry.name, root)) continue;
          const rel = relativeTo(entry.name, root);
          if (/\.html?$/i.test(rel) && !rel.startsWith('assets/')) site.htmlMap.set(rel, entry);
          else if (rel.startsWith('assets/')) site.assets.push(entry);
          else if (ownName(rel).toLowerCase() === 'contacts.csv' && !rel.includes('/')) site.contacts.push(entry);
        }
        return site;
      }).filter(site => site.htmlMap.size);
      if (!state.sites.length) throw new Error('Unable to identify websites in this ZIP.');
      const labelCounts = new Map(), usedExportNames = new Set();
      for (const site of state.sites) labelCounts.set(slug(site.label), (labelCounts.get(slug(site.label)) || 0) + 1);
      for (const site of state.sites) {
        const preferred = labelCounts.get(slug(site.label)) > 1 ? slug(site.root.replaceAll('/', '-')) : slug(site.label === 'Website' ? 'solo-website' : site.label);
        let unique = preferred, number = 2;
        while (usedExportNames.has(unique)) unique = preferred + '-' + number++;
        site.outputLabel = unique; usedExportNames.add(unique);
      }

      const csvEntries = all.filter(e => ownName(e.name).toLowerCase() === 'images.csv' && !e.name.includes('__MACOSX/'));
      const htmlCache = new Map();
      async function getHtml(entry) {
        if (!htmlCache.has(entry.name)) htmlCache.set(entry.name, await state.zip.readText(entry));
        return htmlCache.get(entry.name);
      }
      let assigned = 0, unassigned = 0;
      for (const csvEntry of csvEntries) {
        let rows;
        try { rows = parseCsv(await state.zip.readText(csvEntry)); }
        catch (error) { state.warnings.push(`${csvEntry.name}: ${error.message}`); continue; }
        const csvDir = dirname(csvEntry.name);
        const specific = state.sites.find(site => csvDir === site.root);
        for (const raw of rows) {
          const url = raw['image url'].trim();
          if (!validateImageUrl(url)) { state.warnings.push(`Skipped an invalid or unsafe image URL in ${csvEntry.name}, row ${raw.sourceRow}.`); continue; }
          const candidates = specific ? [specific] : state.sites;
          const found = [];
          for (const site of candidates) {
            const target = htmlFileForPage(site, raw.page.trim());
            if (!target) {
              if (specific || candidates.length === 1) found.push({ site, target: null });
              continue;
            }
            if (specific || candidates.length === 1 || htmlContains(await getHtml(site.htmlMap.get(target)), url)) found.push({ site, target });
          }
          for (const { site, target } of found) {
            if (!target) state.warnings.push(`${site.label}: page ${raw.page} for image row ${raw.sourceRow} was not found; the image will still be downloaded.`);
            site.rows.push({ page: raw.page, location: raw.location.trim(), url, target, sourceRow: raw.sourceRow, filename: '', warning: '' });
            assigned++;
          }
          if (!found.length) unassigned++;
        }
      }
      if (!csvEntries.length) state.warnings.push('No images.csv found. HTML and assets can still be exported, but remote images will not be localised.');
      if (unassigned) state.warnings.push(`${unassigned} CSV image row(s) could not be matched to a site/page. Their references will remain unchanged.`);

      // Assign deterministic, collision-safe local filenames. Never use URLs as output filenames.
      for (const site of state.sites) {
        const chosenPaths = new Map(), exact = new Map();
        for (const row of site.rows) {
          const same = `${row.location}\u0000${row.url}`;
          if (exact.has(same)) { row.filename = exact.get(same); continue; }
          const base = slug(row.location);
          let attempt = base, counter = 2;
          while (chosenPaths.has(attempt)) attempt = `${base}-${counter++}`;
          chosenPaths.set(attempt, true);
          row.filename = attempt; exact.set(same, attempt);
        }
      }
      for (const site of state.sites) {
        for (const row of site.rows) if (!state.images.has(row.url)) state.images.set(row.url, { url: row.url, status: 'queued', bytes: null, format: null, error: null, preview: null });
      }
      // Top-level contacts are separated, never placed in a site bundle.
      state.globalContacts = all.filter(e => ownName(e.name).toLowerCase() === 'contacts.csv' &&
        !state.sites.some(site => site.contacts.includes(e)) && !e.name.includes('__MACOSX/'));
      state.warnings.push(...state.sites.filter(s => s.htmlMap.size === 0).map(s => `${s.label}: no HTML files.`));
      $('summary-filename').textContent = file.name;
      $('summary-stats').textContent = `${state.sites.length} website(s) · ${assigned} image references · ${state.images.size} unique image URLs · ${formatSize(file.size)} original ZIP`;
      $('results').classList.remove('d-none');
      renderSites(); renderGlobalContacts(); renderWarnings(); updateUI();
      clearMessage();
      $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (state.images.size) await fetchAllImages(current);
      if (current === state.generation) updateUI();
    } catch (err) {
      if (current === state.generation) { releaseSession(); showMessage(err.message || 'Could not process this ZIP.'); }
    } finally {
      if (current === state.generation) state.processing = false;
      browseButton.disabled = false;
    }
  }

  function readRemoteImage(url, generation) {
    return new Promise((resolve, reject) => {
      const req = new XMLHttpRequest();
      state.activeRequests.add(req);
      let oversized = false;
      req.open('GET', url, true);
      req.responseType = 'arraybuffer'; req.timeout = 45000; req.withCredentials = false;
      req.onprogress = event => { if (event.loaded > MAX_IMAGE_BYTES) { oversized = true; req.abort(); } };
      req.onload = () => {
        state.activeRequests.delete(req);
        if (generation !== state.generation) return reject(new Error('Cancelled'));
        if (req.status < 200 || req.status >= 300) return reject(new Error(`HTTP ${req.status}`));
        const bytes = new Uint8Array(req.response || new ArrayBuffer(0));
        if (!bytes.length) return reject(new Error('Empty image response'));
        if (bytes.length > MAX_IMAGE_BYTES) return reject(new Error('Image exceeds 25 MB limit'));
        const format = imageFormat(bytes);
        if (!format) return reject(new Error('Not a supported raster image (SVG is excluded)'));
        resolve({ bytes, format });
      };
      req.onerror = () => { state.activeRequests.delete(req); reject(new Error('Download failed (possibly CORS, network or expired URL)')); };
      req.ontimeout = () => { state.activeRequests.delete(req); reject(new Error('Timed out')); };
      req.onabort = () => { state.activeRequests.delete(req); reject(new Error(oversized ? 'Image exceeds 25 MB limit' : 'Cancelled')); };
      try { req.send(); } catch (error) { state.activeRequests.delete(req); reject(error); }
    });
  }
  async function fetchAllImages(generation, urls = [...state.images.keys()]) {
    let next = 0;
    const jobs = Array.from({ length: Math.min(CONCURRENCY, urls.length) }, async () => {
      while (next < urls.length && generation === state.generation) {
        const url = urls[next++], image = state.images.get(url);
        if (!image || image.status === 'complete') continue;
        image.status = 'loading'; updateUI();
        try {
          const result = await readRemoteImage(url, generation);
          if (generation !== state.generation) return;
          image.bytes = result.bytes; image.format = result.format; image.status = 'complete'; image.error = null;
          image.preview = URL.createObjectURL(new Blob([result.bytes], { type: result.format.mime }));
          state.objectUrls.push(image.preview);
        } catch (err) {
          if (generation !== state.generation) return;
          image.status = 'error'; image.error = err.message || 'Download failed';
        }
        updateUI();
      }
    });
    await Promise.all(jobs);
  }

  function renderWarnings() {
    const node = $('global-warnings');
    node.replaceChildren(); node.classList.toggle('d-none', !state.warnings.length);
    if (!state.warnings.length) return;
    const block = makeElement('div', 'warning-list');
    for (const warning of state.warnings) block.append(makeElement('div', '', `⚠ ${warning}`));
    node.append(block);
  }
  function addButton(label, className, callback) {
    const btn = makeElement('button', `btn ${className}`, label);
    btn.type = 'button'; btn.addEventListener('click', callback);
    return btn;
  }
  function downloadBlob(blob, filename) {
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = href; anchor.download = filename;
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(href), 60000);
  }
  async function saveContacts(entry, button) {
    button.disabled = true;
    try {
      const bytes = await state.zip.read(entry);
      downloadBlob(new Blob([bytes], { type: 'text/csv;charset=utf-8' }), ownName(entry.name));
    } catch (err) { showMessage(`Could not extract contacts: ${err.message}`); }
    finally { button.disabled = false; }
  }
  function renderGlobalContacts() {
    const node = $('global-contacts'); node.replaceChildren();
    node.classList.toggle('d-none', state.globalContacts.length === 0);
    for (const entry of state.globalContacts) {
      const card = makeElement('div', 'site-card d-flex flex-wrap justify-content-between align-items-center gap-2');
      const description = makeElement('div');
      description.append(makeElement('strong', '', 'Shared contacts file'), makeElement('div', 'site-info', entry.name));
      const button = addButton('Download contacts CSV', 'btn-outline-secondary', () => saveContacts(entry, button));
      card.append(description, button); node.append(card);
    }
  }
  function renderSites() {
    const list = $('site-list'); list.replaceChildren();
    for (const site of state.sites) {
      const card = makeElement('article', 'site-card');
      const head = makeElement('div', 'd-flex justify-content-between align-items-start flex-wrap gap-2 mb-3');
      const left = makeElement('div');
      left.append(makeElement('div', 'site-heading', site.label), makeElement('div', 'site-path', site.root || '(archive root)'));
      const chip = makeElement('span', 'status-chip', 'Checking images');
      head.append(left, chip); card.append(head);
      const counts = makeElement('div', 'site-summary mb-3', `${site.htmlMap.size} HTML file(s) · ${site.assets.length} asset file(s) · ${site.rows.length} image reference(s)`);
      card.append(counts);
      const actions = makeElement('div', 'site-actions');
      const exportBtn = addButton('Download website ZIP', 'btn-violet px-3', () => buildWebsite(site));
      actions.append(exportBtn);
      for (const contactEntry of site.contacts) {
        const button = addButton('Download contacts CSV', 'btn-outline-secondary', () => saveContacts(contactEntry, button));
        actions.append(button);
      }
      const retryBtn = addButton('Retry failed images', 'btn-outline-secondary', () => {
        const urls = [...new Set(site.rows.map(r => r.url))].filter(url => state.images.get(url).status === 'error');
        fetchAllImages(state.generation, urls);
      });
      actions.append(retryBtn);
      const addLocal = addButton('Add images manually', 'btn-outline-secondary', () => input.click());
      const input = makeElement('input', 'visually-hidden'); input.type = 'file'; input.accept = 'image/png,image/jpeg,image/webp,image/gif,image/avif,image/bmp'; input.multiple = true;
      input.addEventListener('change', async () => { await importImages(site, [...input.files]); input.value = ''; });
      actions.append(addLocal, input);
      card.append(actions);
      const info = makeElement('div', 'site-info mt-2', 'Manual matching: choose images saved using the original URL filename or the Location-based filename shown below.');
      card.append(info);
      const status = makeElement('div', 'site-info mt-3'); card.append(status);
      let imageRows = [];
      if (site.rows.length) {
        const details = makeElement('details', 'image-details');
        const summary = makeElement('summary', '', 'Review image references');
        details.append(summary);
        const ul = makeElement('ul', 'image-list');
        for (const row of site.rows) {
          const li = makeElement('li', 'image-row');
          const thumb = makeElement('span', 'thumb', '▧');
          const txt = makeElement('div', 'image-row-details');
          txt.append(makeElement('div', 'image-title', row.location || '(Unnamed image)'),
            makeElement('div', 'image-subtitle', `${row.target || '(page missing)'} · img/${row.filename}.[type]`));
          const originalLink = makeElement('a', 'image-original-link', 'Open original image');
          originalLink.href = row.url;
          originalLink.target = '_blank';
          originalLink.rel = 'noopener noreferrer';
          originalLink.referrerPolicy = 'no-referrer';
          txt.append(originalLink);
          const imageStatus = makeElement('span', 'image-state', 'Queued');
          li.append(thumb, txt, imageStatus); ul.append(li);
          imageRows.push({ row, thumb, imageStatus, txt });
        }
        details.append(ul); card.append(details);
      }
      list.append(card);
      site.ui = { card, chip, exportBtn, retryBtn, status, imageRows };
    }
  }

  function updateUI() {
    if (!state.sites.length) return;
    const images = [...state.images.values()];
    const processed = images.filter(im => im.status === 'complete' || im.status === 'error').length;
    const fraction = images.length ? Math.round(100 * processed / images.length) : 100;
    $('overall-progress').style.width = fraction + '%';
    $('overall-progress').parentElement.setAttribute('aria-valuenow', String(fraction));
    $('progress-label').textContent = processed === images.length ? 'Image checks complete' : 'Downloading images';
    $('progress-count').textContent = `${processed} / ${images.length}`;
    const incompleteAllowed = $('allow-incomplete').checked;
    for (const site of state.sites) {
      const ui = site.ui; if (!ui) continue;
      const required = new Set(site.rows.map(r => r.url));
      let complete = 0, failed = 0, loading = 0;
      for (const url of required) {
        const im = state.images.get(url);
        if (im.status === 'complete') complete++;
        else if (im.status === 'error') failed++;
        else loading++;
      }
      const ready = loading === 0 && failed === 0;
      const statusText = site.rows.length ? (failed ? `${failed} image(s) unavailable` : loading ? `Fetching ${loading} image(s)` : 'Images ready') : 'No image downloads';
      ui.chip.textContent = statusText;
      ui.chip.className = `status-chip ${failed ? 'problem' : loading ? 'busy' : 'ready'}`;
      ui.status.textContent = `${complete} / ${required.size} image URL(s) saved locally` + (failed ? ` · ${failed} failed. You can retry or import these images manually.` : '');
      ui.exportBtn.disabled = site.building || loading > 0 || (failed > 0 && !incompleteAllowed);
      ui.exportBtn.textContent = site.building ? 'Building ZIP…' : 'Download website ZIP';
      ui.retryBtn.disabled = failed === 0;
      for (const entry of ui.imageRows) {
        const im = state.images.get(entry.row.url);
        entry.imageStatus.textContent = im.status === 'complete' ? 'Saved' : im.status === 'error' ? 'Failed' : im.status === 'loading' ? 'Fetching…' : 'Queued';
        entry.imageStatus.className = `image-state ${im.status === 'complete' ? 'ok' : im.status === 'error' ? 'fail' : ''}`;
        entry.imageStatus.title = im.error || '';
        if (im.preview && entry.thumb.tagName !== 'IMG') {
          const img = makeElement('img', 'thumb'); img.alt = ''; img.src = im.preview;
          entry.thumb.replaceWith(img); entry.thumb = img;
        }
        if (im.format) entry.txt.children[1].textContent = `${entry.row.target || '(page missing)'} · img/${entry.row.filename}.${im.format.ext}`;
      }
    }
  }

  async function importImages(site, files) {
    let matched = 0, skipped = 0;
    const tokens = new Map();
    for (const row of site.rows) {
      const im = state.images.get(row.url);
      if (im.status === 'complete') continue;
      let original;
      try { original = decodeURIComponent(new URL(row.url).pathname.split('/').at(-1)); } catch { original = ''; }
      const names = [original, `${row.filename}.jpg`, `${row.filename}.jpeg`, `${row.filename}.png`,
        `${row.filename}.webp`, `${row.filename}.gif`, `${row.filename}.avif`, `${row.filename}.bmp`];
      for (const n of names) if (n) {
        const key = n.toLowerCase();
        if (!tokens.has(key)) tokens.set(key, new Set());
        tokens.get(key).add(row.url);
      }
    }
    for (const file of files) {
      const urls = tokens.get(file.name.toLowerCase());
      if (!urls || urls.size !== 1) { skipped++; continue; } // Ambiguous filename: never guess.
      const url = [...urls][0], image = state.images.get(url);
      if (file.size > MAX_IMAGE_BYTES) { skipped++; continue; }
      const bytes = new Uint8Array(await file.arrayBuffer()), format = imageFormat(bytes);
      if (!format) { skipped++; continue; }
      image.bytes = bytes; image.format = format; image.status = 'complete'; image.error = null;
      image.preview = URL.createObjectURL(new Blob([bytes], { type: format.mime }));
      state.objectUrls.push(image.preview);
      matched++;
    }
    updateUI();
    showMessage(`${matched} image(s) matched and imported${skipped ? `; ${skipped} file(s) skipped because of unmatched/ambiguous filenames or unsupported formats` : ''}.`, matched ? 'success' : 'warning');
  }

  async function buildWebsite(site) {
    if (!state.zip || site.building) return;
    const generation = state.generation;
    const missing = [...new Set(site.rows.map(r => r.url))].filter(url => state.images.get(url).status !== 'complete');
    if (missing.length && !$('allow-incomplete').checked) {
      showMessage(`Cannot export ${site.label}: ${missing.length} image(s) are missing. Retry or enable incomplete exports.`); return;
    }
    site.building = true; updateUI(); clearMessage();
    try {
      const files = [], outputNames = new Set(), counts = { replacements: 0, unmatched: site.rows.filter(row => !row.target).length };
      for (const [path, entry] of site.htmlMap) {
        let html = await state.zip.readText(entry);
        const rows = site.rows.filter(row => row.target === path);
        for (const row of rows) {
          const im = state.images.get(row.url);
          if (im.status !== 'complete') continue;
          const depth = path.split('/').length - 1;
          const local = '../'.repeat(depth) + `img/${row.filename}.${im.format.ext}`;
          const result = replaceUrl(html, row.url, local);
          html = result.html;
          if (!result.matches) counts.unmatched++;
          counts.replacements += result.matches;
        }
        files.push({ name: path, data: encoder.encode(html) }); outputNames.add(path);
      }
      for (const entry of site.assets) {
        const path = relativeTo(entry.name, site.root);
        if (outputNames.has(path)) continue;
        files.push({ name: path, data: await state.zip.read(entry) }); outputNames.add(path);
      }
      for (const row of site.rows) {
        const im = state.images.get(row.url);
        if (im.status !== 'complete') continue;
        const path = `img/${row.filename}.${im.format.ext}`;
        if (outputNames.has(path)) continue;
        files.push({ name: path, data: im.bytes }); outputNames.add(path);
      }
      if (generation !== state.generation) return;
      const oversize = files.filter(file => file.data.length > CLOUDFLARE_ASSET_LIMIT);
      const tooMany = files.length > CLOUDFLARE_DRAG_DROP_FILES_LIMIT;
      const deploymentWarnings = [];
      if (tooMany) deploymentWarnings.push(`${files.length} files exceeds Cloudflare dashboard's 1,000-file drag-and-drop limit (use Wrangler for eligible sites)`);
      if (oversize.length) deploymentWarnings.push(`${oversize.length} file(s) exceed Cloudflare Pages' 25 MiB per-file limit`);
      const zip = await makeZip(files);
      if (generation !== state.generation) return;
      downloadBlob(zip, filenameForSite(site));
      if (counts.unmatched || missing.length || deploymentWarnings.length) {
        showMessage(`ZIP generated for ${site.label}. Attention: ${counts.unmatched} CSV image reference(s) were not found in their target HTML, ${missing.length} image(s) were unavailable. ${deploymentWarnings.join('; ')}. Inspect your published site.`, 'warning');
      } else {
        showMessage(`Exported ${site.label}: ${files.length} files with ${counts.replacements} remote image reference(s) relinked locally.`, 'success');
      }
    } catch (err) {
      showMessage(`Failed to create ZIP for ${site.label}: ${err.message}`);
    } finally { site.building = false; updateUI(); }
  }

  // Interaction setup: no submitted ZIP/CSV/site content is ever added to the DOM as HTML.
  const dropzone = $('dropzone');
  dropzone.addEventListener('click', evt => { if (evt.target.id !== 'browse-btn') $('zip-input').click(); });
  dropzone.addEventListener('keydown', evt => {
    if (evt.key === 'Enter' || evt.key === ' ') { evt.preventDefault(); $('zip-input').click(); }
  });
  $('browse-btn').addEventListener('click', evt => { evt.stopPropagation(); $('zip-input').click(); });
  $('zip-input').addEventListener('change', evt => {
    const file = evt.target.files?.[0]; if (file) inspectArchive(file);
    evt.target.value = '';
  });
  for (const name of ['dragenter', 'dragover']) dropzone.addEventListener(name, event => {
    event.preventDefault(); event.stopPropagation(); dropzone.classList.add('dragover');
  });
  for (const name of ['dragleave', 'drop']) dropzone.addEventListener(name, event => {
    event.preventDefault(); event.stopPropagation(); dropzone.classList.remove('dragover');
  });
  dropzone.addEventListener('drop', event => {
    const file = event.dataTransfer.files?.[0];
    if (file) inspectArchive(file);
  });
  $('reset-btn').addEventListener('click', () => { releaseSession(); clearMessage(); window.scrollTo({ top: 0, behavior: 'smooth' }); });
  $('allow-incomplete').addEventListener('change', updateUI);
})();
