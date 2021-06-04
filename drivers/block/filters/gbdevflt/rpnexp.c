// SPDX-License-Identifier: GPL-2.0-only
/*
 * Implements parser for RPN and processor for bytecode.
 */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include "rpnexp.h"

/*
 * Limit on the maximum bytecode size.
 * 64KiB is enough for everyone
 */
#define RPN_BYTECODE_LIMIT 8192
#define RPN_BYTECODE_MINIMUM 16

/*
 * A little bit about the implementation.
 *
 * To achieve maximum performance, bytecode and a virtual processor are used
 * to execute arithmetic-logical expressions. Yes, I know that there is an eBPF.
 * And I also know about a series of vulnerabilities in it. Using own processor
 * allows to achieve maximum performance when processing simple expressions.
 *
 * The virtual processor uses 8-bit opcodes. This reduces the size of bytecode.
 * If the bytecode is less than 128 bytes, it can fit in a single cache line.
 *
 * The processor uses only the virtual stack. There are no virtual registers.
 * A virtual stack is created on the stack of the function that called
 * the expression. The stack is 64-bit. The stack is protected from overflow.
 * The stack size is undefined. Its size determines the code that causes the
 * expression to be executed.
 *
 * The constants used by the bytecode are 64-bit. They are stored in the same
 * memory block as the operations. This allows to store them in the same
 * cache line.
 *
 * There are no locks. All data is on the stack only, which allows to
 * execute a single bytecode in multiple processes at the same time.
 *
 * All this allows to squeeze out the maximum performance for executing
 * simple arithmetic-logical expressions. If you think that the existing
 * restrictions are not enough for your task, use eBPF.
 *
 * 8 bit opcode structure
 *
 * The most significant bit in the opcode byte separates the built-in
 * operations from the external ones.
 *
 * For build-in operations, 2 bits are used to separate operations into types.
 * The division into types allows to optimize opcode decoder.
 * +-+--+-----+
 * |1|tp|  n  |
 * +-+--+-----+
 *
 * tp - 2 bits for operation type
 *	00b - service operations
 *	01b - unary operation
 *	10b - operation with two variables
 *
 * The remaining 5 bits allows to have 32 operations for each types.
 *
 * For external commands, the highest bit is zero.
 * +-+-------+
 * |0|   n   |
 * +-+-------+
 * The remaining 7 bits allows to have a dictionary of 128 commands.
 *
 */

/*
 * Build-in basic operations
 */
#define RPN_OP_TYPE_MASK	0xE0
#define RPN_OP_BUILDIN_NUM_MASK	0x1F

#define RPN_SERVICE_OP	0x80
#define RPN_UNARY_OP	0xA0
#define RPN_TWO_OP	0xC0


/* low level service operations */
enum {
	RPN_OP_END = RPN_SERVICE_OP,	/* byte code termination operation */
	RPN_OP_LD			/* load data and push to stack     */
};

/* operations with two variables */
static u64 rpn_op_add(u64 v0, u64 v1)
{
	return v0 + v1;
}
static u64 rpn_op_sub(u64 v0, u64 v1)
{
	return v0 - v1;
}
static u64 rpn_op_mul(u64 v0, u64 v1)
{
	return v0 * v1;
}
static u64 rpn_op_div(u64 v0, u64 v1)
{
	return v0 / v1;
}
static u64 rpn_op_bool_or(u64 v0, u64 v1)
{
	return v0 || v1;
}
static u64 rpn_op_bool_and(u64 v0, u64 v1)
{
	return v0 && v1;
}

struct rpn_two_op {
	const char *name;
	u64 (*fn)(u64, u64);
};

static const struct rpn_two_op rpn_two_op_dict[] = {
	{"+", rpn_op_add},
	{"-", rpn_op_sub},
	{"*", rpn_op_mul},
	{"/", rpn_op_div},
	{"||", rpn_op_bool_or},
	{"&&", rpn_op_bool_and},
	{NULL, NULL}
};

/* unary operations */
static u64 rpn_op_bool_not(u64 v0)
{
	return !v0;
}

struct rpn_unary_op {
	const char *name;
	u64 (*fn)(u64);
};

static const struct rpn_unary_op rpn_unary_op_dict[] = {
	{"!", rpn_op_bool_not},
	{NULL, NULL}
};

struct rpn_bytecode_state {
	size_t ops_ofs;
	size_t data_ofs;
	size_t ops_len;
	size_t data_len;
};

/* searching in two operations build-in dictionary */
static bool find_buildin_two_op(const char *word, size_t length, u8 *opcode)
{
	const struct rpn_two_op *op = rpn_two_op_dict;
	u8 inx = 0;

	while (op[inx].name != NULL) {
		if (length == strlen(op[inx].name))
			if (strncmp(op[inx].name, word, length) == 0) {
				*opcode = RPN_TWO_OP | inx;
				return true;
			}
		inx++;
	}

	return false;
}

/* searching in unary operations build-in dictionary */
static bool find_buildin_unary_op(const char *word, size_t length, u8 *opcode)
{
	const struct rpn_unary_op *op = rpn_unary_op_dict;
	u8 inx = 0;

	while (op[inx].name != NULL) {
		if (length == strlen(op[inx].name))
			if (strncmp(op[inx].name, word, length) == 0) {
				*opcode = RPN_UNARY_OP | inx;
				return true;
			}
		inx++;
	}

	return false;
}

/* searching in extended dictionary*/
static bool find_ext_op(const char *word, size_t length,
			const struct rpn_ext_op *op_dict, u8 *opcode)
{
	size_t inx = 0;

	while (op_dict[inx].name != NULL) {
		if (length == strlen(op_dict[inx].name))
			if (strncmp(op_dict[inx].name, word, length) == 0) {
				*opcode = inx;
				return true;
			}
		inx++;
	}

	return false;
}

static int rpn_bytecode_append_op(struct rpn_bytecode *bc,
				  struct rpn_bytecode_state *state, u8 op)
{
	void *buffer;

	if (unlikely(state->ops_ofs == state->ops_len)) {
		if (state->ops_len)
			state->ops_len = state->ops_len << 1;
		else
			state->ops_len = RPN_BYTECODE_MINIMUM;

		buffer = krealloc(bc->ops, state->ops_len, GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;

		bc->ops = buffer;
	}

	bc->ops[state->ops_ofs++] = op;
	return 0;
}

static int rpn_bytecode_append_data(struct rpn_bytecode *bc,
				    struct rpn_bytecode_state *state, u64 value)
{
	void *buffer;

	if (unlikely(state->data_ofs == state->data_len)) {
		if (state->data_len)
			state->data_len = state->data_len << 1;
		else
			state->data_len = RPN_BYTECODE_MINIMUM;

		buffer = krealloc(bc->data, state->data_len * sizeof(u64),
				    GFP_KERNEL);
		if (!buffer)
			return -ENOMEM;

		bc->data = buffer;
	}

	bc->data[state->data_ofs++] = value;
	return 0;
}

static inline int rpn_parse_constant(char *word, size_t length, u64 *value)
{
	int ret;
	char *word_str;

	word_str = kmemdup_nul(word, length, GFP_KERNEL);
	ret = kstrtou64(word_str, 0, value);
	kfree(word_str);

	return ret;
}

static int rpn_parse_word(char *word, size_t length,
			  const struct rpn_ext_op *ext_op_dict,
			  struct rpn_bytecode *bc,
			  struct rpn_bytecode_state *state)
{
	int ret = 0;
	u8 opcode;
	u64 value;

	if (find_buildin_two_op(word, length, &opcode))
		goto append_op;

	if (find_buildin_unary_op(word, length, &opcode))
		goto append_op;

	if (ext_op_dict && find_ext_op(word, length, ext_op_dict, &opcode))
		goto append_op;

	/* parse constant and put to bytecode data segment*/
	ret = rpn_parse_constant(word, length, &value);
	if (ret)
		return ret;

	ret = rpn_bytecode_append_data(bc, state, value);
	if (ret)
		return ret;
	opcode = RPN_OP_LD;

append_op:
	return rpn_bytecode_append_op(bc, state, opcode);
}

static int combine_segments(struct rpn_bytecode *bc,
			    struct rpn_bytecode_state *state)
{
	void *buffer;
	size_t aligned_len;
	size_t data_len;

	aligned_len = (state->ops_ofs + (sizeof(u64) - 1)) & ~(sizeof(u64) - 1);
	data_len = state->data_ofs * sizeof(u64);

	buffer = kzalloc(aligned_len + data_len, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	memcpy(buffer, bc->ops, state->ops_ofs);
	kfree(bc->ops);
	bc->ops = buffer;

	memcpy(buffer + aligned_len, bc->data, data_len);
	kfree(bc->data);
	bc->data = (buffer + aligned_len);

	return 0;
}

/**
 * rpn_parse_expression() - parse string expression in RPN to bytecode
 * @exp: expression in RPN
 * @op_ext_dict: dictionary of external operations.
 * @bc: bytecode structure
 *
 * Description:
 * If successful, the function return zero and  block of memory with the
 * generated byte code will be initialized in @bc.
 * We will need to take care of freeing this memory by calling
 * rpn_release_bytecode().
 *
 * If the expression was not parsed correctly, the function returns
 * an error code.
 */
int rpn_parse_expression(char *exp, const struct rpn_ext_op *op_ext_dict,
			 struct rpn_bytecode *bc)
{
	int ret = 0;
	char *word = NULL;
	size_t inx = 0;
	size_t length;
	struct rpn_bytecode_state state = {0};

	while (exp[inx] != '\0') {
		if ((exp[inx] != ' ') && (exp[inx] != '\t')) {
			if (word == NULL)
				word = &exp[inx];
			++inx;
			continue;
		}

		if (word) {
			length = (size_t)(exp + inx - word);
			ret = rpn_parse_word(word, length, op_ext_dict, bc, &state);
			if (ret)
				goto fail;
			word = NULL;
		}
		++inx;
	}

	if (word) {
		length = (size_t)(exp + inx - word);
		ret = rpn_parse_word(word, length, op_ext_dict, bc, &state);
		if (ret)
			goto fail;
	}

	/* put the end of program operation */
	ret = rpn_bytecode_append_op(bc, &state, RPN_OP_END);
	if (ret)
		goto fail;

	/* combine opcode and data segment to single memory block */
	if (bc->data) {
		ret = combine_segments(bc, &state);
		if (ret)
			goto fail;
	}
	return 0;
fail:
	kfree(bc->data);
	kfree(bc->ops);

	return ret;
}

/**
 * rpn_execute_bytecode() - execute bytecode
 * @bc: copy of bytecode structure on stack
 * @op_ext_dict: extended operations dictionary
 * @stack: data stack defined by RPN_STACK()
 * @ctx: context for extended operations
 *
 * Description:
 * This function should be optimized to ensure minimum bytecode processing time.
 * Thread safety is ensured by the fact that each call uses its own stack.
 */
int rpn_execute_bytecode(struct rpn_bytecode bc,
			 const struct rpn_ext_op *op_ext_dict,
			 struct rpn_stack *stack, void *ctx)
{
	int ret = 0;
	u64 v0, v1;
	u8 opcode;
	const struct rpn_two_op *two_op;
	const struct rpn_unary_op *unary_op;

next_opcode:
	opcode = *bc.ops++;
	switch (opcode & RPN_OP_TYPE_MASK) {
	case RPN_SERVICE_OP:
		switch (opcode) {
		case RPN_OP_LD:
			/*
			 * Get constant from data segment and push to stack
			 */
			v0 = *bc.data++;
			ret = rpn_stack_push(stack, v0);
			if (unlikely(ret))
				return ret;
			break;
		case RPN_OP_END:
			return 0;
		default:
			return -EOPNOTSUPP;
		}
		break;
	case RPN_UNARY_OP:
		/*
		 * Get one value from stack and execute unary operation.
		 */
		ret = rpn_stack_pop(stack, &v0);
		if (unlikely(ret))
			return ret;

		unary_op = rpn_unary_op_dict + (opcode & RPN_OP_BUILDIN_NUM_MASK);
		v0 = unary_op->fn(v0);

		ret = rpn_stack_push(stack, v0);
		if (unlikely(ret))
			return ret;
		break;
	case RPN_TWO_OP:
		/*
		 * Get two values from stack and execute operation.
		 */
		ret = rpn_stack_pop_double(stack, &v0, &v1);
		if (unlikely(ret))
			return ret;

		two_op = rpn_two_op_dict + (opcode & RPN_OP_BUILDIN_NUM_MASK);
		v0 = two_op->fn(v0, v1);

		ret = rpn_stack_push(stack, v0);
		if (unlikely(ret))
			return ret;
		break;
	default:
		ret = (op_ext_dict + opcode)->fn(stack, ctx);
		if (unlikely(ret))
			return ret;
	}
	goto next_opcode;
}
