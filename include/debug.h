#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>

#define DEBUG	1

static inline void qlog(const char *format, ...)
{
	va_list args;

	if (!DEBUG)
		return;

	va_start(args, format);
	printf("[QUIC]: ");
	vprintf(format, args);
	va_end(args);
}

static char *format_hex(uint8_t *res, const uint8_t *s, size_t len)
{
	int i;

	memset(res, 0, 128);
	for (i = 0; i < len; i++)
		sprintf(res + (i * 2), "%02x", s[i]);

	return res;
}

static void print_secrets(const uint8_t *secret, size_t secretlen, const uint8_t *key,
			  size_t keylen, const uint8_t *iv, size_t ivlen, const uint8_t *hp,
			  size_t hplen)
{
	char res[128];

	if (secret)
		qlog("+ secret=%s\n", format_hex(res, secret, secretlen));
	if (key)
		qlog("+ key=%s\n", format_hex(res, key, keylen));
	if (iv)
		qlog("+ iv=%s\n", format_hex(res, iv, ivlen));
	if (hp)
		qlog("+ hp=%s\n", format_hex(res, hp, hplen));
}
