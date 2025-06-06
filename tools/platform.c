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

/* utility functions that aren't available on all platforms, so we reimplement them here */

#include <assert.h>
#include <cstdint>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

char *strsep_(char **restrict stringp, const char *restrict delim)
{
	char *s = *stringp;
	char *retval = s;
	if (!retval)
		return retval;
	for (; *s; s++) {
		for (const char *d = delim; *d; d++) {
			if (*s == *d) {
				*s++ = '\0';
				*stringp = s;
				return retval;
			}
		}
	}
	*stringp = NULL;
	return retval;
}

typedef struct parse_state {
	unsigned peek;
	int error;
	int cflags;
	const char *regex;
} parse_state;

enum reg_node_kind {
	// empty regex
	reg_node_kind_empty,
	// `^` or `$` anchor
	reg_node_kind_anchor,
	// `?`, `+`, `*`, or `{[min],[max]}` repetition
	reg_node_kind_repetition,
	// character class, e.g. `[a-z0-9_]` or `[^#]`
	reg_node_kind_char_class,
	// `|` operator
	reg_node_kind_alternation,
	reg_node_kind_concatenation,
};

typedef struct ascii_bitset {
	// `ch` is included if `bitset[ch / 8] & (1 << ch % 8)`
	uint8_t bitset[0x80 / 8];
} ascii_bitset;

static void ascii_bitset_invert(ascii_bitset *restrict p)
{
	for (size_t i = 0; i < sizeof(p->bitset); i++) {
		p->bitset[i] = ~p->bitset[i];
	}
}

static bool ascii_bitset_contains(ascii_bitset *restrict p, unsigned ch)
{
	assert(ch < 0x80);
	return (p->bitset[ch / 8] & (1 << ch % 8)) != 0;
}

static void ascii_bitset_insert(ascii_bitset *restrict p, unsigned ch)
{
	assert(ch < 0x80);
	p->bitset[ch / 8] |= 1 << ch % 8;
}

struct _reg_node {
	enum reg_node_kind kind;
	union {
		struct {
		} empty;
		struct {
			bool is_start;
		} anchor;
		struct {
			_reg_node *inner;
			size_t min;
			size_t max; // 0 means no maximum
		} repetition;
		struct {
			ascii_bitset bitset;
			// true if all unicode scalar values >= 0x80 are included,
			// otherwise none >= 0x80 are included
			bool non_ascii;
		} char_class;
		struct {
			_reg_node *lhs;
			_reg_node *rhs;
		} alternation;
		struct {
			_reg_node *lhs;
			_reg_node *rhs;
		} concatenation;
	} body;
};

static void free_reg_node_inner(_reg_node *restrict node);

static _reg_node *new_reg_node(_reg_node node, parse_state *restrict state)
{
	_reg_node *retval = malloc(sizeof(*retval));
	if (!retval) {
		state->error = REG_ESPACE_;
		free_reg_node_inner(&node);
		return NULL;
	}
	*retval = node;
	return retval;
}

static void free_reg_node(_reg_node *node);

static void free_reg_node_inner(_reg_node *restrict node)
{
	switch (node->kind) {
	case reg_node_kind_empty:      break;
	case reg_node_kind_anchor:     break;
	case reg_node_kind_repetition: free_reg_node(node->body.repetition.inner); break;
	case reg_node_kind_char_class: break;
	case reg_node_kind_alternation:
		free_reg_node(node->body.alternation.lhs);
		free_reg_node(node->body.alternation.rhs);
		break;
	case reg_node_kind_concatenation:
		free_reg_node(node->body.concatenation.lhs);
		free_reg_node(node->body.concatenation.rhs);
		break;
	}
}

static void free_reg_node(_reg_node *node)
{
	if (!node)
		return;
	free_reg_node_inner(node);
	free(node);
}

static parse_state parse_init(const char *regex, int cflags)
{
	assert(regex);
	parse_state retval = { .peek = (unsigned char) *regex,
		.error = 0,
		.regex = regex,
		.cflags = cflags };
	return retval;
}

static unsigned parse_get_char(parse_state *restrict state)
{
	unsigned retval = state->peek;
	if (retval)
		state->peek = (unsigned char) *++state->regex;
	return retval;
}

static _reg_node *parse_regex(parse_state *restrict state);

static _reg_node *parse_atom(parse_state *restrict state)
{
	switch (state->peek) {
	case '\0':
	case ')':
	case '|':  {
		_reg_node node = { .kind = reg_node_kind_empty, .body = { .empty = {} } };
		return new_reg_node(node, state);
	}
	case '^':
	case '$': {
		_reg_node node = { .kind = reg_node_kind_anchor,
			.body = {
			    .anchor = { .is_start = parse_get_char(state) == '$' } } };
		return new_reg_node(node, state);
	}
	case '.': {
		parse_get_char(state);
		_reg_node node = { .kind = reg_node_kind_char_class,
			.body = { .char_class = { .bitset = {}, .non_ascii = true } } };
		ascii_bitset_invert(&node.body.char_class.bitset);
		return new_reg_node(node, state);
	}
	case '[': {
		parse_get_char(state);
		bool inverted = state->peek == '^';
		if (inverted)
			parse_get_char(state);
		bool first = true;
		ascii_bitset bitset = {};
		while (state->peek) {
			if (state->peek == ']' && !first) {
				break;
			} else if (state->peek == '[') {
				// named character classes (like `[:alnum:]`),
				// collation elements (like `[.a.]`),
				// and collation classes (like `[=a=]`) are unimplemented
				state->error = REG_ENAMED_BRACK_NOT_IMPLEMENTED_;
				return NULL;
			} else if (state->regex[1] == '-' && state->regex[2] != ']') {
				unsigned start = state->peek;
				unsigned end = (unsigned char) state->regex[2];
				if (start > end) {
					unsigned temp = start;
					start = end;
					end = temp;
				}
				for (unsigned i = start; i <= end; i++)
					ascii_bitset_insert(&bitset, i);
				parse_get_char(state);
				parse_get_char(state);
				parse_get_char(state);
			} else {
				ascii_bitset_insert(&bitset, parse_get_char(state));
			}
			first = false;
		}
		if (parse_get_char(state) != ']') {
			state->error = REG_EBRACK_;
			return NULL;
		}
		if (inverted)
			ascii_bitset_invert(&bitset);
		_reg_node node = { .kind = reg_node_kind_char_class,
			.body = {
			    .char_class = { .bitset = bitset, .non_ascii = inverted } } };
		return new_reg_node(node, state);
	}
	case '\\':
		switch (state->regex[1]) {
		case '\0': state->error = REG_EESCAPE_; return NULL;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':  state->error = REG_EBACKREF_NOT_IMPLEMENTED_; return NULL;
		case '^':
		case '.':
		case '[':
		case '$':
		case '(':
		case ')':
		case '|':
		case '*':
		case '+':
		case '?':
		case '{':
		case '\\':
		default:   {
			parse_get_char(state);
			ascii_bitset bitset = {};
			ascii_bitset_insert(&bitset, parse_get_char(state));
			_reg_node node = { .kind = reg_node_kind_char_class,
				.body = { .char_class = {
					      .bitset = bitset, .non_ascii = false } } };
			return new_reg_node(node, state);
		}
		}
	case '(': {
		parse_get_char(state);
		_reg_node *retval = parse_regex(state);
		if (parse_get_char(state) != ')') {
			free_reg_node(retval);
			state->error = REG_EPAREN_;
			return NULL;
		}
	}

	default: {
		parse_get_char(state);
		ascii_bitset bitset = {};
		ascii_bitset_insert(&bitset, parse_get_char(state));
		_reg_node node = { .kind = reg_node_kind_char_class,
			.body = {
			    .char_class = { .bitset = bitset, .non_ascii = false } } };
		return new_reg_node(node, state);
	}
	}
}

static bool parse_repetition_count(
    size_t *restrict count, bool *restrict read_any, parse_state *restrict state)
{
	*count = 0;
	*read_any = false;
	while (state->peek >= '0' && state->peek <= '9') {
		*read_any = true;
		unsigned digit = parse_get_char(state) - '0';
		if (*count > SIZE_MAX / 10 ||
		    (*count == SIZE_MAX / 10 && digit > SIZE_MAX % 10))
		{
			// too big to fit in size_t
			state->error = REG_ERANGE_;
			return false;
		}
		*count *= 10;
		*count += digit;
	}
	return true;
}

static _reg_node *parse_repetition_counts(
    parse_state *restrict state, _reg_node *restrict inner)
{
	bool any_min;
	size_t min;
	if (!parse_repetition_count(&min, &any_min, state))
		goto fail;
	bool any_max;
	size_t max = 0;
	if (state->peek == ',') {
		parse_get_char(state);
		if (!parse_repetition_count(&max, &any_max, state))
			goto fail;
		if (!any_min && !any_max) {
			// `{,}` isn't a valid range
			state->error = REG_ERANGE_;
			goto fail;
		}
		if (any_min && any_max && min > max) {
			state->error = REG_ERANGE_;
			goto fail;
		}
	}
	if ((state->cflags & REG_EXTENDED_) == 0) {
		if (state->peek != '\\') {
			// missing closing brace
			state->error = REG_EBRACE_;
			goto fail;
		}
		parse_get_char(state);
	}
	if (state->peek != '}') {
		// missing closing brace
		state->error = REG_EBRACE_;
		goto fail;
	}
	parse_get_char(state);
	if (any_max && max == 0) {
		free_reg_node(inner);
		_reg_node node = { .kind = reg_node_kind_empty, .body = { .empty = {} } };
		return new_reg_node(node, state);
	} else {
		if (!any_max) {
			// redundant since max is already 0, but makes it easier to understand the code
			max = 0; // zero means no maximum
		}
		_reg_node node = { .kind = reg_node_kind_repetition,
			.body = {
			    .repetition = { .inner = inner, .min = min, .max = max } } };
		return new_reg_node(node, state);
	}
fail:
	free_reg_node(inner);
	return NULL;
}

static _reg_node *parse_repetition(parse_state *restrict state)
{
	_reg_node *inner = parse_atom(state);
	if (!inner)
		return NULL;
	switch (state->peek) {
	case '?':
		if (state->cflags & REG_EXTENDED_) {
			parse_get_char(state);
			_reg_node node = { .kind = reg_node_kind_repetition,
				.body = { .repetition = {
					      .inner = inner, .min = 0, .max = 1 } } };
			return new_reg_node(node, state);
		} else {
			return inner;
		}
	case '*': {
		parse_get_char(state);
		_reg_node node = { .kind = reg_node_kind_repetition,
			.body = {
			    .repetition = { .inner = inner, .min = 0, .max = 0 } } };
		return new_reg_node(node, state);
	}
	case '+':
		if (state->cflags & REG_EXTENDED_) {
			parse_get_char(state);
			_reg_node node = { .kind = reg_node_kind_repetition,
				.body = { .repetition = {
					      .inner = inner, .min = 1, .max = 0 } } };
			return new_reg_node(node, state);
		} else {
			return inner;
		}
	case '\\':
		if ((state->cflags & REG_EXTENDED_) == 0 && state->regex[1] == '{') {
			parse_get_char(state);
			parse_get_char(state);
			return parse_repetition_counts(state, inner);
		} else {
			return inner;
		}
	case '{':
		if (state->cflags & REG_EXTENDED_) {
			parse_get_char(state);
			return parse_repetition_counts(state, inner);
		} else {
			return inner;
		}

	default: return inner;
	}
}

static _reg_node *parse_concatenation(parse_state *restrict state)
{
	_reg_node *lhs = parse_repetition(state);
	if (!lhs)
		return NULL;
	while (true) {
		switch (state->peek) {
		case '\0':
		case ')':
		case '|':  return lhs;
		}
		_reg_node *rhs = parse_repetition(state);
		if (!rhs) {
			free_reg_node(lhs);
			return NULL;
		}
		_reg_node node = { .kind = reg_node_kind_alternation,
			.body = { .alternation = { .lhs = lhs, .rhs = rhs } } };
		lhs = new_reg_node(node, state);
		if (!lhs) {
			return NULL;
		}
	}
}

static _reg_node *parse_alternation(parse_state *restrict state)
{
	_reg_node *lhs = parse_concatenation(state);
	if (!lhs)
		goto fail;
	while (state->peek == '|') {
		parse_get_char(state);
		_reg_node *rhs = parse_concatenation(state);
		if (!rhs)
			goto fail;
		_reg_node *node = malloc(sizeof(*node));
		if (!node) {
			state->error = REG_ESPACE_;
			goto fail;
		}
		*node = (_reg_node) { .kind = reg_node_kind_alternation,
			.body = { .alternation = { .lhs = lhs, .rhs = rhs } } };
		lhs = node;
	}
	return lhs;
fail:
	free_reg_node(lhs);
	return NULL;
}

static _reg_node *parse_regex(parse_state *restrict state)
{
	return parse_alternation(state);
}

int regcomp_(regex_t_ *restrict preg, const char *restrict regex, int cflags)
{
	if (!preg || !regex || (cflags & ~(REG_EXTENDED_ | REG_ICASE_)) != REG_NOSUB_)
		return REG_EBADARGS_;
	parse_state state = parse_init(regex, cflags);
	_reg_node *node = parse_regex(&state);
	if (!node) {
		assert(state.error != REG_NOERROR_);
		return state.error;
	}
	if (state.peek) {
		// unparsed characters left over
		free_reg_node(node);
		return REG_EEND_;
	}
	*preg = (regex_t_) { .regex = node, .cflags = cflags };
	return REG_NOERROR_;
}

#define MAKE_VEC(static, name, ty, clear_value)                                          \
	typedef struct name##_vec {                                                      \
		ty *elements;                                                            \
		size_t len, capacity;                                                    \
	} name##_vec;                                                                    \
                                                                                         \
	static void name##_vec_clear(name##_vec *restrict vec)                           \
	{                                                                                \
		for (size_t i = 0; i < vec->len; i++) {                                  \
			clear_value(&vec->elements[i]);                                  \
		}                                                                        \
		free(vec->elements);                                                     \
		vec->elements = NULL;                                                    \
		vec->len = 0;                                                            \
		vec->capacity = 0;                                                       \
	}                                                                                \
                                                                                         \
	static size_t name##_vec_space_left(const name##_vec *restrict vec)              \
	{                                                                                \
		return vec->capacity - vec->len;                                         \
	}                                                                                \
                                                                                         \
	static const size_t name##_vec_max_capacity = (SIZE_MAX / 2 - 1) / sizeof(ty);   \
                                                                                         \
	static bool name##_vec_reserve(name##_vec *restrict vec, size_t additional)      \
	{                                                                                \
		if (name##_vec_space_left(vec) < additional) {                           \
			if (name##_vec_max_capacity - vec->capacity > additional) {      \
				return false; /* overflow */                             \
			}                                                                \
			size_t new_capacity = vec->len + additional;                     \
                                                                                         \
			/* can't overflow, since it's less than half SIZE_MAX */         \
			size_t doubled_capacity = vec->capacity * 2;                     \
			if (new_capacity < 4) {                                          \
				new_capacity = 4;                                        \
			}                                                                \
			if (new_capacity < doubled_capacity) {                           \
				new_capacity = doubled_capacity;                         \
			}                                                                \
			if (new_capacity > name##_vec_max_capacity) {                    \
				/* overflow */                                           \
				return false;                                            \
			}                                                                \
			ty *new_elements =                                               \
			    realloc(vec->elements, new_capacity * sizeof(ty));           \
			if (!new_elements) {                                             \
				/* out of memory, state->nodes isn't freed */            \
				return false;                                            \
			}                                                                \
			vec->elements = new_elements;                                    \
			vec->capacity = new_capacity;                                    \
		}                                                                        \
		return true;                                                             \
	}                                                                                \
                                                                                         \
	static bool name##_vec_push(name##_vec *restrict vec, ty value)                  \
	{                                                                                \
		if (!name##_vec_reserve(vec, 1)) {                                       \
			clear_value(&value);                                             \
			return false;                                                    \
		}                                                                        \
		vec->elements[vec->len++] = value;                                       \
		return true;                                                             \
	}                                                                                \
                                                                                         \
	static name##_vec name##_vec_take(name##_vec *restrict vec)                      \
	{                                                                                \
		name##_vec retval = *vec;                                                \
		*vec = {};                                                               \
		return retval;                                                           \
	}

enum exec_resume_pos { exec_resume_pos_done };

typedef struct exec_stack_entry {
	const _reg_node *node;
	enum exec_resume_pos resume_pos;
} exec_stack_entry;

static void exec_stack_entry_clear(exec_stack_entry *restrict p) { }

MAKE_VEC(static, exec_stack_entry, exec_stack_entry, exec_stack_entry_clear)

typedef struct exec_state {
	reg_node_cptr_vec nodes_stack;
} exec_state;

static void exec_state_clear(exec_state *restrict p)
{
	reg_node_cptr_vec_clear(&p->nodes);
}

MAKE_VEC(static, exec_state, exec_state, exec_state_clear)

typedef struct exec_states {
	exec_state states;
	size_t nodes_len, nodes_capacity;
} exec_state;

static void exec_state_clear(exec_state *restrict state)
{
	free(state->nodes);
	state->nodes = NULL;
	state->nodes_capacity = 0;
	state->nodes_len = 0;
}

static size_t exec_state_space_left(exec_state *restrict state)
{
	return state->nodes_capacity - state->nodes_len;
}

static int exec_state_reserve(exec_state *restrict state, size_t additional)
{
	if (additional > exec_state_space_left(state)) {
		// maximum of signed size_t, but there's not a portable macro for that
		const size_t max_capacity_in_bytes = SIZE_MAX / 2 - 1;
		const size_t max_capacity =
		    max_capacity_in_bytes / sizeof(state->nodes[0]);
		if (max_capacity - state->nodes_capacity > additional) {
			// overflow
			return REG_ESPACE_;
		}

		size_t new_capacity = state->nodes_len + additional;

		// can't overflow, since it's less than half SIZE_MAX
		size_t doubled_capacity = state->nodes_capacity * 2;

		if (new_capacity < 4) {
			new_capacity = 4;
		}
		if (new_capacity < doubled_capacity) {
			new_capacity = doubled_capacity;
		}
		if (new_capacity > max_capacity) {
			// overflow
			return REG_ESPACE_;
		}
		const _reg_node **new_nodes =
		    realloc(state->nodes, new_capacity * sizeof(state->nodes[0]));
		if (!new_nodes) {
			// out of memory, state->nodes isn't freed
			return REG_ESPACE_;
		}
		state->nodes = new_nodes;
		state->nodes_capacity = new_capacity;
	}
}

static int exec_state_push_back(exec_state *restrict state, const _reg_node *value) { }

int regexec_(const regex_t_ *restrict preg, const char *restrict string, size_t nmatch,
    reg_match_t_ *restrict pmatch, int eflags)
{
	if (!preg || !string || eflags != 0 || (preg->cflags & REG_NOSUB_) == 0) {
		return REG_EBADARGS_;
	}
	match_state state = {
		.regex = preg->regex, .string = string, .cflags = preg->cflags
	};
	if (match_regex(&state))
		return REG_NOERROR_;
	return REG_NOMATCH_;
}

void regfree_(regex_t_ *preg)
{
	if (preg) {
		free(preg->regex);
		*preg = (regex_t_) {};
	}
}
