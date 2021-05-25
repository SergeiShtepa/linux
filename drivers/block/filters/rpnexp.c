#include <linux/types.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include "rpnexp.h"

/*
 * Limit on the maximum bytecode size.
 * 64KiB is enough for everyone
 */
#define RPN_BYTECODE_LIMIT (65536 / sizeof(u64))
#define RPN_BYTECODE_MINIMUM (32 / sizeof(u64))

/*
 * Build-in basic operations
 */
/* low level service operations */
#define RPN_SERVICE_OP 0x01000000
enum {
	RPN_OP_END = RPN_SERVICE_OP,	/* byte code termination operation */
	RPN_OP_CALL			/* load address and call */
};

/* operations with two variables */
#define RPN_TWO_OP 0x02000000
enum {
	RPN_OP_ADD = RPN_TWO_OP,	/* get to integers from stack, add and
					   push result back */
	RPN_OP_SUB,			/* also but for subtraction */
	RPN_OP_MUL,
	RPN_OP_DIV,
	RPN_OP_BOOL_OR,			/* boolean 'or' */
	RPN_OP_BOOL_AND
};

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
static u64 (* const rpn_two_op_fn[])(u64, u64) = {
	rpn_op_add,
	rpn_op_sub,
	rpn_op_mul,
	rpn_op_div,
	rpn_op_bool_or,
	rpn_op_bool_and
};

/* unary operations */
#define RPN_UNARY_OP 0x04000000
enum {
	RPN_OP_BOOL_NOT = RPN_UNARY_OP
};
static u64 rpn_op_bool_not(u64 v0)
{
	return !v0;
}
static u64 (*const rpn_unary_op_fn[])(u64)  = {
	rpn_op_bool_not
};

struct rpn_buildin_op {
	const char * name;
	u64 code;
};

static const struct rpn_buildin_op rpn_buildin_op_dict[] = {
	{"+", RPN_OP_ADD},
	{"-", RPN_OP_SUB},
	{"*", RPN_OP_MUL},
	{"/", RPN_OP_DIV},
	{"&&", RPN_OP_BOOL_AND},
	{"||", RPN_OP_BOOL_OR},
	{"!", RPN_OP_BOOL_NOT},
	{NULL, 0}
};

/* searching in build-in dictionary */
static bool find_buildin_op(const char *word, size_t length, u64 *opcode)
{
	const struct rpn_buildin_op *op = rpn_buildin_op_dict;
	size_t inx = 0;

	while (op[inx].name != NULL) {
		if (length == strlen(op[inx].name))
			if (strncmp(op[inx].name, word, length) == 0) {
				*opcode = op[inx].code;
				return true;
			}
		inx++;
	}

	return false;
}

/* searching in extended dictionary*/
static bool find_ext_op(const char *word, size_t length,
			const struct rpn_ext_op *op, u64 *opcode)
{
	size_t inx = 0;

	while (op[inx].name != NULL) {
		if (length == strlen(op[inx].name))
			if (strncmp(op[inx].name, word, length) == 0) {
				*opcode = (u64)op[inx].fn;
				return true;
			}
		inx++;
	}

	return false;
}

struct rpn_bytecode {
	u64 *head;
	size_t ofs;
	size_t len;
};

static inline int rpn_bytecode_append(struct rpn_bytecode *bc, u64 value)
{
	if (unlikely(bc->ofs == bc->len)) {
		if (bc->len == 0) {
			bc->len = RPN_BYTECODE_MINIMUM;
			bc->head = kzalloc(sizeof(u64) * bc->len, GFP_KERNEL);
			if (!bc->head)
				return -ENOMEM;
		} else {
			bc->len = bc->len << 1;
			bc->head = krealloc(bc->head, sizeof(u64) * bc->len,
					    GFP_KERNEL);
			if (!bc->head)
				return -ENOMEM;
		}
	}

	bc->head[bc->ofs++] = value;
	return 0;
}

static int rpn_parse_word(char *word, size_t length,
			  const struct rpn_ext_op *ext_op_dict,
			  struct rpn_bytecode *bc)
{
	int ret = 0;
	u64 opcode;

	if (find_buildin_op(word, length, &opcode)) {
		/* put buildin opcode */
		return rpn_bytecode_append(bc, opcode);
	}

	if (ext_op_dict) {
		if (find_ext_op(word, length, ext_op_dict, &opcode)) {
			/* put external operations address */
			ret = rpn_bytecode_append(bc, opcode);
			if(ret)
				return ret;
			/* put call operation */
			return rpn_bytecode_append(bc, RPN_OP_CALL);
		}
	}

	ret = kstrtou64(word, 0, &opcode);
	if (ret)
		return ret;
	/* put constant */
	return rpn_bytecode_append(bc, opcode);
}

/**
 *
 *
 * Compile string expression in RPN to fast executable byte code
 */
u64* rpn_parse_expression(char *exp, const struct rpn_ext_op *op_dict)
{
	int ret = 0;
	struct rpn_bytecode bc = {0};
	char *word = NULL;
	size_t inx = 0;

	while(exp[inx] != '\0') {
		if ((exp[inx] != ' ') && (exp[inx] != '\t')) {
			if (word == NULL)
				word = &exp[inx];
			++inx;
			continue;
		}

		if (word) {
			size_t length = (size_t)(&exp[inx] - word);

			ret = rpn_parse_word(word, length, op_dict, &bc);
			if (ret)
				goto fail;
			word = NULL;
		}
		++inx;
	}

	if (word) {
		size_t length = (size_t)(&exp[inx] - word);

		ret = rpn_parse_word(word, length, op_dict, &bc);
		if (ret)
			goto fail;
	}

	/* put the end of program operation */
	ret = rpn_bytecode_append(&bc, RPN_OP_END);
	if (ret)
		goto fail;

	return bc.head;
fail:
	kfree(bc.head);

	return ERR_PTR(ret);
}

/**
 *
 *
 * Execute byte code
 */
int rpn_execute(u64 *op, struct rpn_stack *stack, void *ctx)
{
	int ret = 0;
	u64 opcode;

	while((opcode = *op++) != RPN_OP_END) {
		pr_err("DEBUG! opcode=%llx", opcode);
		if (opcode & RPN_SERVICE_OP) {
			if (opcode == RPN_OP_CALL) {
				u64 v0;

				ret = rpn_stack_pop(stack, &v0);
				if (unlikely(ret))
					return ret;
				pr_err("DEBUG! call=%llx", v0);
				ret = ((int(*)(struct rpn_stack *, void *))(v0))
					(stack, ctx);
				if (unlikely(ret))
					return ret;
			} else
				return -ENOTSUPP;
		} else if (opcode & RPN_UNARY_OP) {
			u64 v0;
			/*
			 * Get one integer from stack and execute
			 * unary operation.
			 */
			ret = rpn_stack_pop(stack, &v0);
			if (unlikely(ret))
				return ret;
			pr_err("DEBUG! unary op %llx for %llx", opcode - RPN_UNARY_OP, v0);
			v0 = rpn_unary_op_fn[opcode - RPN_UNARY_OP](v0);

			ret = rpn_stack_push(stack, v0);
			if (unlikely(ret))
				return ret;
		} else if (opcode & RPN_TWO_OP) {
			u64 v0, v1;
			/*
			 * Get two integer from stack and execute operation.
			 */
			ret = rpn_stack_pop_double(stack, &v0, &v1);
			if (unlikely(ret))
				return ret;
			pr_err("DEBUG! two op %llx for %llx,%llx ", opcode - RPN_UNARY_OP, v0, v1);
			v0 = rpn_two_op_fn[opcode - RPN_TWO_OP](v0, v1);

			ret = rpn_stack_push(stack, v0);
			if (unlikely(ret))
				return ret;
		} else {
			/*
			 * get constant from byte code
			 * and push to stack
			 */
			pr_err("DEBUG! push constant");
			ret = rpn_stack_push(stack, opcode);
			if (unlikely(ret))
				return ret;
		}
	}

	return ret;
}

char* rpn_bytecode_to_dbgstr(u64 *op)
{
	char* str;
	char* tail;
	size_t len = 4096;
	u64 opcode = 0;
	size_t word_len = 0;

	str = kzalloc(4096, GFP_KERNEL);
	if (!str)
		return ERR_PTR(-ENOMEM);

	tail = str;

	while((opcode = *op++) != RPN_OP_END) {
		if (len < 32) {
			snprintf(tail, len, "...\n");
			break;
		}

		snprintf(tail, len, "%llx ", opcode);
		word_len = strlen(tail);
		len -= word_len;
		tail += word_len;
	}
	if (opcode != 0)
		snprintf(tail, len, "%llx", opcode);

	return str;
}
