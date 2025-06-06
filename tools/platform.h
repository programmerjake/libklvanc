/*
 * Copyright (c) 2025 Jacob Lifshay <programmerjake@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* utility functions that aren't available on all platforms, so we reimplement them here */

/** like `strsep` from glibc */
char *strsep_(char **restrict stringp, const char *restrict delim);

typedef struct _reg_node _reg_node;

/** ultra-simplistic regex.h re-implementation */
typedef struct regex_t_ {
	_reg_node *regex;
	int cflags;
} regex_t_;

/* returning regex matches isn't implemented */
typedef struct reg_match_t_ reg_match_t_;

enum {
	REG_EXTENDED_ = 1 << 0,
	REG_ICASE_ = 1 << 1,
	REG_NOSUB_ = 1 << 2,
};

enum {
	REG_NOERROR_ = 0,
	REG_NOMATCH_,
	REG_ESPACE_,
	REG_EBADARGS_,
	REG_EEND_,
	REG_ERANGE_,
	REG_EBRACE_,
	REG_EBRACK_,
	REG_EESCAPE_,
	REG_EPAREN_,
	REG_ENAMED_BRACK_NOT_IMPLEMENTED_,
	REG_EBACKREF_NOT_IMPLEMENTED_,
};

int regcomp_(regex_t_ *restrict preg, const char *restrict regex, int cflags);
int regexec_(const regex_t_ *restrict preg, const char *restrict string, size_t nmatch,
    reg_match_t_ *restrict pmatch, int eflags);
void regfree_(regex_t_ *preg);

#ifdef __cplusplus
}
#endif

#endif
