#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "handshake.h"

static int read_psk_file(char *psk, char *identity[], gnutls_datum_t *pkey)
{
	unsigned char *end, *key, *buf;
	int fd, err = -1, i = 0;
	struct stat statbuf;
	gnutls_datum_t gkey;
	unsigned int size;

	fd = open(psk, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;

	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}

	end = buf + size - 1;
	do {
		key = strchr(buf, ':');
		if (!key)
			goto out;
		*key = '\0';
		identity[i] = buf;

		key++;
		gkey.data = key;

		buf = strchr(key, '\n');
		if (!buf) {
			gkey.size = end - gkey.data;
			buf = end;
			goto decode;
		}
		*buf = '\0';
		buf++;
		gkey.size = strlen(gkey.data);
decode:
		if (gnutls_hex_decode2(&gkey, &pkey[i]))
			goto out;
		i++;
	} while (buf < end);

	err = i;
out:
	close(fd);
	return err;
}

static int read_datum(const char *file, gnutls_datum_t *data)
{
	struct stat statbuf;
	unsigned int size;
	int ret = -1;
	void *buf;
	int fd;

	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;
	if (fstat(fd, &statbuf))
		goto out;
	if (statbuf.st_size < 0 || statbuf.st_size > INT_MAX)
		goto out;
	size = (unsigned int)statbuf.st_size;
	buf = malloc(size);
	if (!buf)
		goto out;
	if (read(fd, buf, size) == -1) {
		free(buf);
		goto out;
	}
	data->data = buf;
	data->size = size;
	ret = 0;
out:
	close(fd);
	return ret;
}

static int read_pkey_file(char *file, gnutls_privkey_t *privkey)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_privkey_init(privkey);
	if (ret)
		goto out;

	ret = gnutls_privkey_import_x509_raw(*privkey, &data, GNUTLS_X509_FMT_PEM, NULL, 0);
out:
        free(data.data);
	return ret;
}

static int read_cert_file(char *file, gnutls_pcert_st **cert)
{
	gnutls_datum_t data;
	int ret;

	if (read_datum(file, &data))
		return -1;

	ret = gnutls_pcert_import_x509_raw(*cert, &data, GNUTLS_X509_FMT_PEM, 0);
	free(data.data);

	return ret;
}
