/*

BOI - The "Bussin OK Image" format for fast, lossless image compression of
.boi image format for 2023>udctf>rev>Bussin

Dominic Szablewski - https://phoboslab.org


-- LICENSE: The MIT License(MIT)

Copyright(c) 2021 Dominic Szablewski

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files(the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and / or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions :
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


-- About

BOI encodes and decodes images in a lossless format. An encoded BOI image is
usually around 10--30% larger than a decently optimized PNG image.

BOI outperforms simpler PNG encoders in compression ratio and performance. BOI
images are typically 20% smaller than PNGs written with stbi_image. Encoding is
25-50x faster and decoding is 3-4x faster than stbi_image or libpng.


-- Synopsis

// Define `BOI_IMPLEMENTATION` in *one* C/C++ file before including this
// library to create the implementation.

#define BOI_IMPLEMENTATION
#include "boi.h"

// Encode and store an RGBA buffer to the file system. The boi_desc describes
// the input pixel data.
boi_write("image_new.boi", rgba_pixels, &(boi_desc){
	.width = 1920,
	.height = 1080,
	.channels = 4,
	.colorspace = BOI_SRGB
});

// Load and decode a BOI image from the file system into a 32bbp RGBA buffer.
// The boi_desc struct will be filled with the width, height, number of channels
// and colorspace read from the file header.
boi_desc desc;
void *rgba_pixels = boi_read("image.boi", &desc, 4);



-- Documentation

This library provides the following functions;
- boi_read    -- read and decode a BOI file
- boi_decode  -- decode the raw bytes of a BOI image from memory
- boi_write   -- encode and write a BOI file
- boi_encode  -- encode an rgba buffer into a BOI image in memory

See the function declaration below for the signature and more information.

If you don't want/need the boi_read and boi_write functions, you can define
BOI_NO_STDIO before including this library.

This library uses malloc() and free(). To supply your own malloc implementation
you can define BOI_MALLOC and BOI_FREE before including this library.

This library uses memset() to zero-initialize the index. To supply your own
implementation you can define BOI_ZEROARR before including this library.


-- Data Format

A BOI file has a 14 byte header, followed by any number of data "chunks" and an
8-byte end marker.

struct boi_header_t {
	char     magic[4];   // magic bytes "JAWN"
	uint32_t width;      // image width in pixels (BE)
	uint32_t height;     // image height in pixels (BE)
	uint8_t  channels;   // 3 = RGB, 4 = RGBA
	uint8_t  colorspace; // 0 = sRGB with linear alpha, 1 = all channels linear
};

The decoder and encoder start with {r: 0, g: 0, b: 0, a: 255} as the previous
pixel value. Pixels are either encoded as
 - a run of the previous pixel
 - an index into an array of previously seen pixels
 - a difference to the previous pixel value in r,g,b
 - full r,g,b or r,g,b,a values

The color channels are assumed to not be premultiplied with the alpha channel
("un-premultiplied alpha").

A running array[69] (zero-initialized) of previously seen pixel values is
maintained by the encoder and decoder. Each pixel that is seen by the encoder
and decoder is put into this array at the position formed by a hash function of
the color value. In the encoder, if the pixel value at the index matches the
current pixel, this index position is written to the stream as BOI_OP_INDEX.
The hash function for the index is:

	index_position = (r * 1337 + g * 420 + b * 1111 + a * 21) % 69

Each chunk starts with a 2- or 8-bit tag, followed by a number of data bits. The
bit length of chunks is divisible by 8 - i.e. all chunks are byte aligned. All
values encoded in these data bits have the most significant bit on the left.

The 8-bit tags have precedence over the 2-bit tags. A decoder must check for the
presence of an 8-bit tag first.

The byte stream's end is marked with 7 0x00 bytes followed a single 0x01 byte.


The possible chunks are:


.------------------- BOI_OP_INDEX ------------------.
|         Byte[0]         |         Byte[1]         |
|  7  6  5  4  3  2  1  0 |  7  6  5  4  3  2  1  0 |
|-------+----------------------+--------------------|
|  0  0 |           index      |1  1  1  1  1  1  1 |
`---------------------------------------------------`
2-bit tag b00
7-bit index into the color index array: 0..68
7-bits of 1s 0b1111111

A valid encoder must not issue 7 or more consecutive BOI_OP_INDEX chunks to the
index 0, to avoid confusion with the 8 byte end marker.


.- BOI_OP_DIFF -----------.
|         Byte[0]         |
|  7  6  5  4  3  2  1  0 |
|-------+-----+-----+-----|
|  0  1 |  dr |  dg |  db |
`-------------------------`
2-bit tag b01
2-bit   red channel difference from the previous pixel between -2..1
2-bit green channel difference from the previous pixel between -2..1
2-bit  blue channel difference from the previous pixel between -2..1

The difference to the current channel values are using a wraparound operation,
so "1 - 2" will result in 255, while "255 + 1" will result in 0.

Values are stored as unsigned integers with a bias of 2. E.g. -2 is stored as
0 (b00). 1 is stored as 3 (b11).


.- BOI_OP_LUMA -------------------------------------.
|         Byte[0]         |         Byte[1]         |
|  7  6  5  4  3  2  1  0 |  7  6  5  4  3  2  1  0 |
|-------+-----------------+-------------+-----------|
|  1  0 |  green diff     |   dr - dg   |  db - dg  |
`---------------------------------------------------`
2-bit tag b10
6-bit green channel difference from the previous pixel -32..31
4-bit   red channel difference minus green channel difference -8..7
4-bit  blue channel difference minus green channel difference -8..7

The green channel is used to indicate the general direction of change and is
encoded in 6 bits. The red and green channels (dr and db) base their diffs off
of the green channel difference and are encoded in 4 bits. I.e.:
	dr_dg = (last_px.r - cur_px.r) - (last_px.g - cur_px.g)
	db_dg = (last_px.b - cur_px.b) - (last_px.g - cur_px.g)

The difference to the current channel values are using a wraparound operation,
so "10 - 13" will result in 253, while "250 + 7" will result in 1.

Values are stored as unsigned integers with a bias of 32 for the green channel
and a bias of 8 for the red and blue channel.


.- BOI_OP_RUN ------------.
|         Byte[0]         |
|  7  6  5  4  3  2  1  0 |
|-------+-----------------|
|  1  1 |       run       |
`-------------------------`
2-bit tag b11
6-bit run-length repeating the previous pixel: 1..62

The run-length is stored with a bias of -1. Note that the run-lengths 63 and 64
(b111110 and b111111) are illegal as they are occupied by the BOI_OP_RGB and
BOI_OP_RGBA tags.


.- BOI_OP_RGB ------------------------------------------.
|         Byte[0]         | Byte[1] | Byte[2] | Byte[3] |
|  7  6  5  4  3  2  1  0 | 7 .. 0  | 7 .. 0  | 7 .. 0  |
|-------------------------+---------+---------+---------|
|  1  1  1  1  1  1  1  0 |   red   |  green  |  blue   |
`-------------------------------------------------------`
8-bit tag b11111110
8-bit   red channel value
8-bit green channel value
8-bit  blue channel value


.- BOI_OP_RGBA ---------------------------------------------------.
|         Byte[0]         | Byte[1] | Byte[2] | Byte[3] | Byte[4] |
|  7  6  5  4  3  2  1  0 | 7 .. 0  | 7 .. 0  | 7 .. 0  | 7 .. 0  |
|-------------------------+---------+---------+---------+---------|
|  1  1  1  1  1  1  1  1 |   red   |  green  |  blue   |  alpha  |
`-----------------------------------------------------------------`
8-bit tag b11111111
8-bit   red channel value
8-bit green channel value
8-bit  blue channel value
8-bit alpha channel value


The byte stream is padded at the end with 8 zero bytes. Since the longest legal
chunk is 5 bytes (BOI_OP_RGBA), with this padding it is possible to check for an
overrun only once per decode loop iteration. These 0x00 bytes also mark the end
of the data stream, as an encoder should never produce 8 consecutive zero bytes
within the stream.

*/


/* -----------------------------------------------------------------------------
Header - Public functions */

#ifndef BOI_H
#define BOI_H

#ifdef __cplusplus
extern "C" {
#endif

/* A pointer to a boi_desc struct has to be supplied to all of boi's functions.
It describes either the input format (for boi_write and boi_encode), or is
filled with the description read from the file header (for boi_read and
boi_decode).

The colorspace in this boi_desc is an enum where
	0 = sRGB, i.e. gamma scaled RGB channels and a linear alpha channel
	1 = all channels are linear
You may use the constants BOI_SRGB or BOI_LINEAR. The colorspace is purely
informative. It will be saved to the file header, but does not affect
en-/decoding in any way. */

#define BOI_SRGB   0
#define BOI_LINEAR 1

typedef struct {
	unsigned int width;
	unsigned int height;
	unsigned char channels;
	unsigned char colorspace;
} boi_desc;

#ifndef BOI_NO_STDIO

/* Encode raw RGB or RGBA pixels into a BOI image and write it to the file
system. The boi_desc struct must be filled with the image width, height,
number of channels (3 = RGB, 4 = RGBA) and the colorspace.

The function returns 0 on failure (invalid parameters, or fopen or malloc
failed) or the number of bytes written on success. */

int boi_write(const char *filename, const void *data, const boi_desc *desc);


/* Read and decode a BOI image from the file system. If channels is 0, the
number of channels from the file header is used. If channels is 3 or 4 the
output format will be forced into this number of channels.

The function either returns NULL on failure (invalid data, or malloc or fopen
failed) or a pointer to the decoded pixels. On success, the boi_desc struct
will be filled with the description from the file header.

The returned pixel data should be free()d after use. */

void *boi_read(const char *filename, boi_desc *desc, int channels);

#endif /* BOI_NO_STDIO */


/* Encode raw RGB or RGBA pixels into a BOI image in memory.

The function either returns NULL on failure (invalid parameters or malloc
failed) or a pointer to the encoded data on success. On success the out_len
is set to the size in bytes of the encoded data.

The returned boi data should be free()d after use. */

void *boi_encode(const void *data, const boi_desc *desc, int *out_len);


/* Decode a BOI image from memory.

The function either returns NULL on failure (invalid parameters or malloc
failed) or a pointer to the decoded pixels. On success, the boi_desc struct
is filled with the description from the file header.

The returned pixel data should be free()d after use. */

void *boi_decode(const void *data, int size, boi_desc *desc, int channels);


#ifdef __cplusplus
}
#endif
#endif /* BOI_H */


/* -----------------------------------------------------------------------------
Implementation */

#ifdef BOI_IMPLEMENTATION
#include <stdlib.h>
#include <string.h>

#ifndef BOI_MALLOC
	#define BOI_MALLOC(sz) malloc(sz)
	#define BOI_FREE(p)    free(p)
#endif
#ifndef BOI_ZEROARR
	#define BOI_ZEROARR(a) memset((a),0,sizeof(a))
#endif

#define BOI_OP_INDEX  0x00 /* 00xxxxxxx1111111 */
#define BOI_OP_DIFF   0x40 /* 01xxxxxx */
#define BOI_OP_LUMA   0x80 /* 10xxxxxx */
#define BOI_OP_RUN    0xc0 /* 11xxxxxx */
#define BOI_OP_RGB    0xfe /* 11111110 */
#define BOI_OP_RGBA   0xff /* 11111111 */

#define BOI_MASK_2    0xc0 /* 11000000 */

#define BOI_COLOR_HASH(C) (C.rgba.r*1337 + C.rgba.g*420 + C.rgba.b*1111 + C.rgba.a*21)
#define BOI_MAGIC \
	(((unsigned int)'J') << 24 | ((unsigned int)'A') << 16 | \
	 ((unsigned int)'W') <<  8 | ((unsigned int)'N'))
#define BOI_HEADER_SIZE 14

/* 2GB is the max file size that this implementation can safely handle. We guard
against anything larger than that, assuming the worst case with 5 bytes per
pixel, rounded down to a nice clean value. 400 million pixels ought to be
enough for anybody. */
#define BOI_PIXELS_MAX ((unsigned int)400000000)

typedef union {
	struct { unsigned char r, g, b, a; } rgba;
	unsigned int v;
} boi_rgba_t;

static const unsigned char boi_padding[8] = {0,0,0,0,0,0,0,1};

void boi_write_32(unsigned char *bytes, int *p, unsigned int v) {
	bytes[(*p)++] = (0xff000000 & v) >> 24;
	bytes[(*p)++] = (0x00ff0000 & v) >> 16;
	bytes[(*p)++] = (0x0000ff00 & v) >> 8;
	bytes[(*p)++] = (0x000000ff & v);
}

unsigned int boi_read_32(const unsigned char *bytes, int *p) {
	unsigned int a = bytes[(*p)++];
	unsigned int b = bytes[(*p)++];
	unsigned int c = bytes[(*p)++];
	unsigned int d = bytes[(*p)++];
	return a << 24 | b << 16 | c << 8 | d;
}

void *boi_encode(const void *data, const boi_desc *desc, int *out_len) {
	int i, max_size, p, run;
	int px_len, px_end, px_pos, channels;
	unsigned char *bytes;
	const unsigned char *pixels;
	boi_rgba_t index[69];
	boi_rgba_t px, px_prev;

	if (
		data == NULL || out_len == NULL || desc == NULL ||
		desc->width == 0 || desc->height == 0 ||
		desc->channels < 3 || desc->channels > 4 ||
		desc->colorspace > 1 ||
		desc->height >= BOI_PIXELS_MAX / desc->width
	) {
		return NULL;
	}

	max_size =
		desc->width * desc->height * (desc->channels + 1) +
		BOI_HEADER_SIZE + sizeof(boi_padding);

	p = 0;
	bytes = (unsigned char *) BOI_MALLOC(max_size);
	if (!bytes) {
		return NULL;
	}

	boi_write_32(bytes, &p, BOI_MAGIC);
	boi_write_32(bytes, &p, desc->width);
	boi_write_32(bytes, &p, desc->height);
	bytes[p++] = desc->channels;
	bytes[p++] = desc->colorspace;


	pixels = (const unsigned char *)data;

	BOI_ZEROARR(index);

	run = 0;
	px_prev.rgba.r = 0;
	px_prev.rgba.g = 0;
	px_prev.rgba.b = 0;
	px_prev.rgba.a = 255;
	px = px_prev;

	px_len = desc->width * desc->height * desc->channels;
	px_end = px_len - desc->channels;
	channels = desc->channels;

	for (px_pos = 0; px_pos < px_len; px_pos += channels) {
		if (channels == 4) {
			px = *(boi_rgba_t *)(pixels + px_pos);
		}
		else {
			px.rgba.r = pixels[px_pos + 0];
			px.rgba.g = pixels[px_pos + 1];
			px.rgba.b = pixels[px_pos + 2];
		}

		if (px.v == px_prev.v) {
			run++;
			if (run == 62 || px_pos == px_end) {
				bytes[p++] = BOI_OP_RUN | (run - 1);
				run = 0;
			}
		}
		else {
			int index_pos;

			if (run > 0) {
				bytes[p++] = BOI_OP_RUN | (run - 1);
				run = 0;
			}

			index_pos = BOI_COLOR_HASH(px) % 69;

			if (index[index_pos].v == px.v) {
				bytes[p++] = (BOI_OP_INDEX >> 1) | index_pos;
				bytes[p++] = (BOI_OP_INDEX << 7) | 0b01111111;
			}
			else {
				index[index_pos] = px;

				if (px.rgba.a == px_prev.rgba.a) {
					signed char vr = px.rgba.r - px_prev.rgba.r;
					signed char vg = px.rgba.g - px_prev.rgba.g;
					signed char vb = px.rgba.b - px_prev.rgba.b;

					signed char vg_r = vr - vg;
					signed char vg_b = vb - vg;

					if (
						vr > -3 && vr < 2 &&
						vg > -3 && vg < 2 &&
						vb > -3 && vb < 2
					) {
						bytes[p++] = BOI_OP_DIFF | (vr + 2) << 4 | (vg + 2) << 2 | (vb + 2);
					}
					else if (
						vg_r >  -9 && vg_r <  8 &&
						vg   > -33 && vg   < 32 &&
						vg_b >  -9 && vg_b <  8
					) {
						bytes[p++] = BOI_OP_LUMA     | (vg   + 32);
						bytes[p++] = (vg_r + 8) << 4 | (vg_b +  8);
					}
					else {
						bytes[p++] = BOI_OP_RGB;
						bytes[p++] = px.rgba.r;
						bytes[p++] = px.rgba.g;
						bytes[p++] = px.rgba.b;
					}
				}
				else {
					bytes[p++] = BOI_OP_RGBA;
					bytes[p++] = px.rgba.r;
					bytes[p++] = px.rgba.g;
					bytes[p++] = px.rgba.b;
					bytes[p++] = px.rgba.a;
				}
			}
		}
		px_prev = px;
	}

	for (i = 0; i < (int)sizeof(boi_padding); i++) {
		bytes[p++] = boi_padding[i];
	}

	*out_len = p;
	return bytes;
}

void *boi_decode(const void *data, int size, boi_desc *desc, int channels) {
	const unsigned char *bytes;
	unsigned int header_magic;
	unsigned char *pixels;
	boi_rgba_t index[69];
	boi_rgba_t px;
	int px_len, chunks_len, px_pos;
	int p = 0, run = 0;

	if (
		data == NULL || desc == NULL ||
		(channels != 0 && channels != 3 && channels != 4) ||
		size < BOI_HEADER_SIZE + (int)sizeof(boi_padding)
	) {
		return NULL;
	}

	bytes = (const unsigned char *)data;

	header_magic = boi_read_32(bytes, &p);
	desc->width = boi_read_32(bytes, &p);
	desc->height = boi_read_32(bytes, &p);
	desc->channels = bytes[p++];
	desc->colorspace = bytes[p++];

	if (
		desc->width == 0 || desc->height == 0 ||
		desc->channels < 3 || desc->channels > 4 ||
		desc->colorspace > 1 ||
		header_magic != BOI_MAGIC ||
		desc->height >= BOI_PIXELS_MAX / desc->width
	) {
		return NULL;
	}

	if (channels == 0) {
		channels = desc->channels;
	}

	px_len = desc->width * desc->height * channels;
	pixels = (unsigned char *) BOI_MALLOC(px_len);
	if (!pixels) {
		return NULL;
	}

	BOI_ZEROARR(index);
	px.rgba.r = 0;
	px.rgba.g = 0;
	px.rgba.b = 0;
	px.rgba.a = 255;

	chunks_len = size - (int)sizeof(boi_padding);
	for (px_pos = 0; px_pos < px_len; px_pos += channels) {
		if (run > 0) {
			run--;
		}
		else if (p < chunks_len) {
			int b1 = bytes[p++];

			if (b1 == BOI_OP_RGB) {
				px.rgba.r = bytes[p++];
				px.rgba.g = bytes[p++];
				px.rgba.b = bytes[p++];
			}
			else if (b1 == BOI_OP_RGBA) {
				px.rgba.r = bytes[p++];
				px.rgba.g = bytes[p++];
				px.rgba.b = bytes[p++];
				px.rgba.a = bytes[p++];
			}
			else if ((b1 & BOI_MASK_2) == BOI_OP_INDEX) {
                int b2 = bytes[p++];
				px = index[ (b1 << 1) | (b2 >> 7) ];
			}
			else if ((b1 & BOI_MASK_2) == BOI_OP_DIFF) {
				px.rgba.r += ((b1 >> 4) & 0x03) - 2;
				px.rgba.g += ((b1 >> 2) & 0x03) - 2;
				px.rgba.b += ( b1       & 0x03) - 2;
			}
			else if ((b1 & BOI_MASK_2) == BOI_OP_LUMA) {
				int b2 = bytes[p++];
				int vg = (b1 & 0x3f) - 32;
				px.rgba.r += vg - 8 + ((b2 >> 4) & 0x0f);
				px.rgba.g += vg;
				px.rgba.b += vg - 8 +  (b2       & 0x0f);
			}
			else if ((b1 & BOI_MASK_2) == BOI_OP_RUN) {
				run = (b1 & 0x3f);
			}

			index[BOI_COLOR_HASH(px) % 69] = px;
		}

		if (channels == 4) {
			*(boi_rgba_t*)(pixels + px_pos) = px;
		}
		else {
			pixels[px_pos + 0] = px.rgba.r;
			pixels[px_pos + 1] = px.rgba.g;
			pixels[px_pos + 2] = px.rgba.b;
		}
	}

	return pixels;
}

#ifndef BOI_NO_STDIO
#include <stdio.h>

int boi_write(const char *filename, const void *data, const boi_desc *desc) {
	FILE *f = fopen(filename, "wb");
	int size;
	void *encoded;

	if (!f) {
		return 0;
	}

	encoded = boi_encode(data, desc, &size);
	if (!encoded) {
		fclose(f);
		return 0;
	}

	fwrite(encoded, 1, size, f);
	fclose(f);

	BOI_FREE(encoded);
	return size;
}

void *boi_read(const char *filename, boi_desc *desc, int channels) {
	FILE *f = fopen(filename, "rb");
	int size, bytes_read;
	void *pixels, *data;

	if (!f) {
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	if (size <= 0) {
		fclose(f);
		return NULL;
	}
	fseek(f, 0, SEEK_SET);

	data = BOI_MALLOC(size);
	if (!data) {
		fclose(f);
		return NULL;
	}

	bytes_read = fread(data, 1, size, f);
	fclose(f);

	pixels = boi_decode(data, bytes_read, desc, channels);
	BOI_FREE(data);
	return pixels;
}

#endif /* BOI_NO_STDIO */
#endif /* BOI_IMPLEMENTATION */
