// Copyright 2014 Sven Peter <sven@fail0verflow.com>
// Licensed under the terms of the GNU GPL, version 2

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#define ENDIAN_BIG	0
#define ENDIAN_LITTLE	1
static unsigned int g_endian = ENDIAN_BIG;

static unsigned int le32(const uint8_t *ptr)
{
	unsigned int res = 0;
	res |= ptr[3] << 24;
	res |= ptr[2] << 16;
	res |= ptr[1] <<  8;
	res |= ptr[0];

	return res;
}

static void wle32(uint8_t *ptr, uint32_t v)
{
	ptr[3] = v >> 24;
	ptr[2] = v >> 16;
	ptr[1] = v >>  8;
	ptr[0] = v;
}

static unsigned int be32(const uint8_t *ptr)
{
	unsigned int res = 0;
	res |= ptr[0] << 24;
	res |= ptr[1] << 16;
	res |= ptr[2] <<  8;
	res |= ptr[3];

	return res;
}

static void wbe32(uint8_t *ptr, uint32_t v)
{
	ptr[0] = v >> 24;
	ptr[1] = v >> 16;
	ptr[2] = v >>  8;
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

	memset(key, 0, 0x80);

	tmp[0] = iv[0] + ~iv[2];
	tmp[1] = iv[1] + ~iv[3];
	tmp[2] = ~tmp[0];
	tmp[3] = ~tmp[1];

	for (unsigned int i = 0; i < 4; ++i) {
		for (unsigned int j = 0; j < 4; ++j) {
			key[i + 8*j + 0] = tmp[i] + iv[j] - 1;
			key[i + 8*j + 4] = tmp[i] - iv[j] - 1;
		}
	}
}

static int mangle_blocks(off_t offset, size_t len, const void *in, void *out, const uint32_t *fullkey)
{
	uint32_t blocks;
	uint32_t word;

	if (offset % 0x80)
		return -1;

	if (len % 0x80)
		return -1;

	blocks = len / 0x80;

	while (blocks--) {
		for (unsigned int i = 0; i < 0x20; ++i) {
			word = read32(in + offset + 4*i);
			word ^= fullkey[i] - offset;
			write32(out + offset + 4*i, word);
		}
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

	fp = fopen(path, "r");
	if (!fp)
		return 0;

	*res = malloc(st.st_size);
	if (!*res)
		return 0;

	fread(*res, st.st_size, 1, fp);
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

	mangle_blocks(off_start, len, ptr, ptr, key);
}

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "Usage: %s [input] [output]\n", argv[0]);
		return -1;
	}

	void *in = NULL;
	size_t in_size = load_file(&in, argv[1]);

	if (!in || in_size == 0) {
		fprintf(stderr, "Unable to open input file.\n");
		return -1;
	}

	if (strncmp((char *)in + 0x24, "Copyright", 9) == 0) {
		g_endian = ENDIAN_BIG;
		deobfuscate(in, 0, 0, 0x100, 0x0a00000 - 0x100);
		deobfuscate(in, 0x0a00000, 0, 0x100, 0x80000 - 0x100);
	} else if(strncmp((char *)in + 0xf24, "Copyright", 9) == 0) {
		g_endian = ENDIAN_BIG;
		deobfuscate(in, 0, 0xf00, 0, 0xf00);
		deobfuscate(in, 0, 0xf00, 0x1000, 0xc00000 - 0x1000);
		deobfuscate(in, 0xc00000, 0x3ff80, 0, 0x3ff80);
	} else if(strncmp((char *)in + 0x124, "Copyright", 9) == 0) {
		g_endian = ENDIAN_LITTLE;
		deobfuscate(in, 0, 0x100, 0, 0x100);
		deobfuscate(in, 0, 0x100, 0x200, 0x1000000 - 0x200);
		//deobfuscate(in, 0x1000000, 0, 0x80, in_size - 0x1000000 - 0x70);
	} else {
		fprintf(stderr, "Unknown input file.\n");
		return -1;
	}

	FILE *fp = fopen(argv[2], "w");
	if (!fp) {
		fprintf(stderr, "Unable to open output file\n");
		return -1;
	}

	fwrite(in, in_size, 1, fp);
	fclose(fp);

	return 0;
}