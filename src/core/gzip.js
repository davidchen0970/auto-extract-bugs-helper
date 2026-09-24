export async function decompressGzip(u8) {
	if (typeof DecompressionStream === 'undefined') {
		throw new Error('此瀏覽器不支援 DecompressionStream，無法解壓縮 gzip');
	}
	const ds = new DecompressionStream('gzip');
	const stream = new Blob([u8]).stream().pipeThrough(ds);
	return new Uint8Array(await new Response(stream).arrayBuffer());
}
