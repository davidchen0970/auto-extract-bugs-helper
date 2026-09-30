// Read a user-picked file (tar / tar.gz / a single report file) into tar
// entries. Shared by single-file preview (load.js) and two-file comparison
// (compare.js).
import { decompressGzip } from './gzip.js';
import { parseTar } from './tar.js';
import { isTarBytes } from './detect.js';

// Returns an entries array: a tar archive expands into its member files, while a
// single report file is wrapped as a single entry.
export async function ingestFile(file) {
	const raw = await file.arrayBuffer();
	let u8 = new Uint8Array(raw);
	const gzHint = /\.(tar\.gz|tgz|gz)$/i.test(file.name);
	const isGz = gzHint || (u8[0] === 0x1f && u8[1] === 0x8b);
	if (isGz) u8 = await decompressGzip(u8);

	if (!isTarBytes(u8)) {
		return [{ name: file.name, type: 'file', size: u8.length, data: u8 }];
	}
	return parseTar(u8);
}
