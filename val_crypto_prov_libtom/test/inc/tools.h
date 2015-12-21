/*
 * tools.h
 *
 *  Created on: Sep 18, 2014
 *      Author: walz
 */

#ifndef TOOLS_H_
#define TOOLS_H_

#include <stdio.h>
#include <stdlib.h>


typedef struct {
	char * pc_data;
	char * pc_type;
} PEM_ELEMENT;


int read_pem_file(char * pc_file, PEM_ELEMENT ** p_elements);

int read_file(char * pc_file, char ** ppc_buf);

int is_base64_char(char c);


#endif /* TOOLS_H_ */
