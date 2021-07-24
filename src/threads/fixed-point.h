#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

/* Basic definitions of fixed point. */
typedef int fixed_t;
/* 14 LSB used for fractional part. */
#define FP_SHIFT_AMOUNT 16
/* Convert a value to a fixed-point value. */
#define FP_CVI2F(X) ((fixed_t)(X << FP_SHIFT_AMOUNT))
/* Get the integer - rounding toward zero. */
#define FP_CVF2I(X) (X >> FP_SHIFT_AMOUNT)
/* Get the rounded integer - rounding to nearest. */
#define FP_CVF2I_ROUND(X) (X >= 0 ? ((X + (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT) \
				            	  : ((X - (1 << (FP_SHIFT_AMOUNT - 1))) >> FP_SHIFT_AMOUNT))
/* Add two fixed-point value. */
#define FP_ADD(X,Y) (X + Y)
/* Add a fixed-point value X and an int value Y. */
#define FP_ADD_MIX(X,Y) (X + (Y << FP_SHIFT_AMOUNT))
/* Subtract two fixed-point value. */
#define FP_SUB(X,Y) (X - Y)
/* Subtract an int value Y from a fixed-point value X. */
#define FP_SUB_MIX(X,Y) (X - (Y << FP_SHIFT_AMOUNT))
/* Multiply two fixed-point value. */
#define FP_MULT(X,Y) ((fixed_t)(((int64_t) X) * Y >> FP_SHIFT_AMOUNT))
/* Multiply a fixed-point value X by an int value Y. */
#define FP_MULT_MIX(X,Y) (X * Y)
/* Divide two fixed-point value. */
#define FP_DIV(X,Y) ((fixed_t)((((int64_t) X) << FP_SHIFT_AMOUNT) / Y))
/* Divide a fixed-point value X by an int value Y. */
#define FP_DIV_MIX(X,Y) (X / Y)

#endif /* threads/fixed-point.h */
