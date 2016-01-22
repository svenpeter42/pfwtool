/* Copyright 2014-2015 Sven Peter <sven@fail0verflow.com>, bootcoder
   Licensed under the terms of the GNU GPL, version 2

   gcc -W -Wall -std=c99 -o ptxfwtool.exe ptxfwtool.c

   28.09.2014 svenpeter   original implementation
   24.06.2015 bootcoder   mingw/windows build support
                          long file recognition
                          implement decompressor for new file types
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

//  Uncomment the line to enable debug info
//#define DEBUG

#define ENDIAN_BIG 0
#define ENDIAN_LITTLE 1
static unsigned int g_endian = ENDIAN_BIG;

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

static unsigned int le16(const uint8_t *ptr) { return (ptr[1] << 8) | ptr[0]; }
static unsigned int le32(const uint8_t *ptr)
{
	unsigned int res = 0;
	res |= ptr[3] << 24;
	res |= ptr[2] << 16;
	res |= ptr[1] << 8;
	res |= ptr[0];

	return res;
}

static void wle32(uint8_t *ptr, uint32_t v)
{
	ptr[3] = v >> 24;
	ptr[2] = v >> 16;
	ptr[1] = v >> 8;
	ptr[0] = v;
}

static unsigned int be16(const uint8_t *ptr) { return (ptr[0] << 8) | ptr[1]; }
static unsigned int be32(const uint8_t *ptr)
{
	unsigned int res = 0;
	res |= ptr[0] << 24;
	res |= ptr[1] << 16;
	res |= ptr[2] << 8;
	res |= ptr[3];

	return res;
}

static void wbe32(uint8_t *ptr, uint32_t v)
{
	ptr[0] = v >> 24;
	ptr[1] = v >> 16;
	ptr[2] = v >> 8;
	ptr[3] = v;
}

static unsigned int read32(const uint8_t *ptr)
{
	if (g_endian == ENDIAN_LITTLE)
		return le32(ptr);
	else
		return be32(ptr);
}

static void write32(uint8_t *ptr, uint32_t v)
{
	if (g_endian == ENDIAN_LITTLE)
		return wle32(ptr, v);
	else
		return wbe32(ptr, v);
}

static void xor32(uint8_t *ptr, uint32_t v) { write32(ptr, read32(ptr) ^ v); }
static void load_iv(const uint8_t *ptr, uint32_t *iv)
{
	iv[0] = read32(ptr);
	iv[1] = read32(ptr + 4);
	iv[2] = read32(ptr + 8);
	iv[3] = read32(ptr + 12);
}

static void calculate_key(const uint32_t *iv, uint32_t *key)
{
	uint32_t tmp[4];

	tmp[0] = iv[0] + ~iv[2];
	tmp[1] = iv[1] + ~iv[3];
	tmp[2] = ~tmp[0];
	tmp[3] = ~tmp[1];

	for (unsigned int i = 0; i < 4; ++i) {
		for (unsigned int j = 0; j < 4; ++j) {
			key[i + 8 * j + 0] = tmp[i] + iv[j] - 1;
			key[i + 8 * j + 4] = tmp[i] - iv[j] - 1;
		}
	}
}

static int mangle_blocks(off_t offset, size_t len, void *bfr, const uint32_t *fullkey)
{
	uint32_t blocks;

	if (offset % 0x80)
		return -1;

	if (len % 0x80)
		return -1;

	blocks = len / 0x80;

	while (blocks--) {
		for (unsigned int i = 0; i < 0x20; ++i)
			xor32(bfr + offset + 4 * i, fullkey[i] - offset);
		offset += 0x80;
	}

	return 0;
}

static size_t load_file(void **res, const char *path)
{
	FILE *fp = NULL;
	struct stat st;

	if (stat(path, &st) != 0)
		return 0;

	fp = fopen(path, "rb");
	if (!fp)
		return 0;

	*res = malloc(st.st_size);
	if (!*res)
		return 0;

	if (fread(*res, st.st_size, 1, fp) != 1)
		return 0;

	fclose(fp);

	return st.st_size;
}

static void deobfuscate(void *bfr, off_t off_base, off_t off_iv, off_t off_start, size_t len)
{
	uint32_t key[32];
	uint32_t iv[4];
	void *ptr;

	ptr = bfr + off_base;

	load_iv(ptr + off_iv, iv);
	calculate_key(iv, key);

	if (mangle_blocks(off_start, len, ptr, key) < 0) {
		fprintf(stderr, "mangle_blocks failed.\n");
		exit(-1);
	}
}

static size_t decompress(uint8_t *out, size_t out_len, uint8_t *in, size_t in_offs, size_t in_len, int subtype)
{
	uint8_t *pend_in = in + in_len + in_offs;
	uint8_t *pstart_out = out;
	uint8_t *pend;
	int map, mask;
	int blk_len;

	in += in_offs;
	for (;;) {
		if (out >= pstart_out + out_len) {
			printf("!!! Missing stream end\n");
			break;
		}

		blk_len = be16(in);
		in += 2;
#ifdef DEBUG
		printf("Blk:%p len:%04X\n", in - (pend_in - in_len) - 2 + in_offs, blk_len);
#endif

		// end of stream
		if (blk_len == 0)
			break;

		if (blk_len == 0xE000) { // special case
			blk_len = (subtype ? 0x6000 : 0xC002);
		} else if (blk_len > 0x8000) {
			printf("!!! incorrect block length\n");
			break;
		}
		if (in + blk_len + 2 + 2 > pend_in) {
			printf("!!! input block is not complete\n");
			break;
		}

		if (blk_len == 0xC002 && subtype == 0) { // raw block type 0
			// copy and restart
			memcpy(out, in, blk_len - 2);
			// TODO what are last two bytes of such block (not zero)?
			out += (blk_len - 2);
			in += blk_len;
			continue;
		} else if (blk_len == 0x6000 && subtype) { // raw block type 1
			memcpy(out, in, blk_len);
			out += blk_len;
			in += blk_len;
			continue;
		}
		// method appears based on LZRW-1A with different extendable length
		mask = 0;
		for (pend = in + blk_len - 2; in < pend;) {
			if (!mask) {
				map = be16(in);
				in += 2;
				mask = 0x8000;
#ifdef DEBUG
				printf("  Map %04X\n", map);
#endif
			} else {
				if (map & mask) { // COPY
					int len = (in[0] & 7) + 3;
					int offs = ((in[0] & 0xF8) << 5) | in[1];
					in += 2;
					// extended "length" field
					if (len == 10)
						do {
							len += *in;
						} while (*(in++) == 0xFF);
#ifdef DEBUG
					printf("  Mask %04X len:%d offs:%X I:%p, O:%p\n", mask, len, offs,
					       in - (pend_in - in_len) + in_offs, out - pstart_out);
#endif
					if (offs == 0) {
						printf("!!! Zero offset\n");
						break;
					}

					while ((len--) > 0) {
						*out = *(out - offs);
						out++;
					}
				} else { // LITERAL
					*(out++) = *(in++);
				}
				mask >>= 1;
			}
		}
		// trailer
		if (be16(in) != 0) {
			printf("!!! Missing block end\n");
			break;
		}
		in += 2;
	}
	return (out - pstart_out);
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [input] [output]\n", argv[0]);
		return -1;
	}

	void *in = NULL;
	size_t in_size = load_file(&in, argv[1]);
	void *out = in;
	size_t out_size = in_size;
	size_t part_size;

	if (!in || in_size == 0) {
		fprintf(stderr, "Unable to open input file.\n");
		return -1;
	}

	if (strncmp((char *)in + 0x24, "Copyright", 9) == 0) {
		g_endian = ENDIAN_BIG;
		deobfuscate(in, 0, 0, 0x100, 0x0a00000 - 0x100);
		deobfuscate(in, 0x0a00000, 0, 0x100, 0x80000 - 0x100);
	} else if (strncmp((char *)in + 0xf24, "Copyright", 9) == 0 && (in_size == 0xc00000 || in_size == 0xC40000)) {
		g_endian = ENDIAN_BIG;
		deobfuscate(in, 0, 0xf00, 0, 0xf00);
		deobfuscate(in, 0, 0xf00, 0x1000, 0xc00000 - 0x1000);
		if (in_size >= 0xc3ff80)
			deobfuscate(in, 0xc00000, 0x3ff80, 0, 0x3ff80);
	} else if (strncmp((char *)in + 0x124, "Copyright", 9) == 0) {
		g_endian = ENDIAN_LITTLE;
		deobfuscate(in, 0, 0x100, 0, 0x100);
		if (in_size > 0x2000020 && strncmp((char *)in + 0x2000010, "Copyright", 9) == 0)
			part_size = 0x2000000;
		else
			part_size = 0x1000000;
		deobfuscate(in, 0, 0x100, 0x200, part_size - 0x200);
		deobfuscate(in, part_size, 0, 0x80, in_size - part_size - 0x80);
	} else if (strncmp((char *)in, "PENTAX K-S", 10) == 0) {
		int subtype = *((uint8_t *)in + 10) - '1';
		if (in_size & 3) {
			fprintf(stderr, "!!! wrong file size\n");
			return -1;
		}
		uint32_t sum = 0;
		for (size_t i = 0; i < in_size; i += 4) {
			sum += le32(in + i);
		}
		if (sum) {
			fprintf(stderr, "!!! wrong checksum: %08X, expected 0\n", sum);
			return -1;
		}
		if (le16(in + 0x1F6) == 0) {
			fprintf(stderr, "!!! not compressed\n");
			return -1;
		}
		out_size = 0x2000000;
		out = malloc(out_size);
		memset(out, 0, out_size);
		/* limit is a position of resource files (0x00800000)
		   0x005FFFFF is empirical limit for minimum of debug output in bad case */
		out_size = decompress((uint8_t *)out, out_size, in, 0x200, min(in_size, 0x005FFFFF), subtype);
		free(in);
		in = NULL;
	} else {
		fprintf(stderr, "Unknown input file.\n");
		return -1;
	}

	FILE *fp = fopen(argv[2], "wb");
	if (!fp) {
		fprintf(stderr, "Unable to open output file\n");
		return -1;
	}

	fwrite(out, out_size, 1, fp);
	fclose(fp);

	free(out);
	return 0;
}
