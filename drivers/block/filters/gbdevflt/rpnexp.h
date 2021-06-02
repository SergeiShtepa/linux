/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Reverse Polish notation (RPN) expression processor.
 * It's allows to recognize rules written in RPN and execute them.
 */
#ifndef __RPNEXP_H__
#define __RPNEXP_H__

struct rpn_stack {
	u64 *roof;
	u64 *top;
	u64 *bottom;
};

#define RPN_STACK(name, size)							\
	u64 name ##_data[size] = {0};						\
	struct rpn_stack name = {						\
		.roof = name ##_data,						\
		.top = name ##_data + size,					\
		.bottom = name ##_data + size					\
	}
struct rpn_bytecode {
	u8 *ops;		/* code segment */
	u64 *data;		/* data segment */
};

static inline int rpn_stack_pop(struct rpn_stack *st, u64 *value)
{
	if (unlikely(st->top == st->bottom))
		return -ENODATA;

	*value = *st->top;
	st->top++;
	return 0;
};

static inline int rpn_stack_pop_double(struct rpn_stack *st, u64 *v0, u64 *v1)
{
	if (unlikely((st->top + 2) > st->bottom))
		return -ENODATA;

	*v1 = st->top[0];
	*v0 = st->top[1];
	st->top += 2;
	return 0;
};

static inline int rpn_stack_push(struct rpn_stack *st, u64 value)
{
	if (unlikely(st->top == st->roof))
		return -ENOMEM;

	st->top--;
	*st->top = value;

	return 0;
};

struct rpn_ext_op {
	const char *name;
	int (*fn)(struct rpn_stack *stack, void *ctx);
};

int rpn_parse_expression(char *exp,
			 const struct rpn_ext_op *op_ext_dict,
			 struct rpn_bytecode *bc);
int rpn_execute_bytecode(struct rpn_bytecode bc,
			 const struct rpn_ext_op *op_ext_dict,
			 struct rpn_stack *stack,
			 void *ctx);
static inline void rpn_release_bytecode(struct rpn_bytecode *bc)
{
	kfree(bc->ops);
};
#endif
