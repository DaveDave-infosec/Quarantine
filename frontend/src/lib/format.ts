export function short(a: string): string {
  return a ? a.slice(0, 6) + "…" + a.slice(-4) : "";
}

export function isSha(s: string): boolean {
  return /^[0-9a-fA-F]{40}$/.test(s.trim());
}

export function isAddr(s: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(s.trim());
}

export function isRawPrefix(s: string): boolean {
  return /^https:\/\/raw\.githubusercontent\.com\/[^/\s]+\/[^/\s]+\/?$/i.test(s.trim());
}

export function blobUrl(rawPrefix: string, sha: string, path: string): string {
  const m = rawPrefix.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/?$/i);
  if (!m) return rawPrefix + sha + "/" + path;
  return `https://github.com/${m[1]}/${m[2]}/blob/${sha}/${path}`;
}

export function rawToBlob(url: string): string {
  const m = url.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/(.+)$/i);
  return m ? `https://github.com/${m[1]}/${m[2]}/blob/${m[3]}` : url;
}
