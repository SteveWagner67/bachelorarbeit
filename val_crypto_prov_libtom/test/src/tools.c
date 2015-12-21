/*
 * tools.c
 *
 *  Created on: Sep 18, 2014
 *      Author: walz
 */

#include "tools.h"


int read_pem_file(char * pc_file, PEM_ELEMENT ** p_elements) {

	/* the number of PEM elements read from file */
	int n = -1;

	/* input buffer */
	char * pc_in_buf;

	/* read file into buffer */
	int i_n_in = read_file(pc_file, &pc_in_buf);

	if (i_n_in >= 0) {


		/* free file buffer */
		free(pc_in_buf);
	}

	/* return the number of PEM elements read from
	 * file (negative number in case an error occurred) */
	return n;
}


int read_file(char * pc_file, char ** ppc_buf) {

	/* the number of bytes read from file */
	int n = -1;

	/* open file */
	FILE * fp = fopen(pc_file, "r");

	if (fp != NULL) {

		/* determine length of file */
		int i_len = 0;
		while (fgetc(fp) != EOF) {
			i_len++;
		}
		rewind(fp);

		/* allocate memory to store file contents (including terminating '\0') */
		char * pc_buf = (char*)malloc((i_len + 1) * sizeof(char));

		if (pc_buf != NULL) {
			/* read from file and add terminating '\0' */
			n = fread(pc_buf, sizeof(char), i_len, fp);
			pc_buf[i_len] = '\0';

			if (ppc_buf != NULL) {
				*ppc_buf = pc_buf;
			}
		}

		/* close file */
		fclose(fp);
	}

	/* return the number of bytes (chars) read from
	 * file (negative number in case an error occurred) */
	return n;
}


int is_base64_char(char c) {
	/* return 1 if c is a valid base64 character and 0 otherwise */
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '/' || c == '+' || c == '=') ? 1 : 0;
}
