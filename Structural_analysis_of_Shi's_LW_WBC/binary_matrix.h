#pragma once
#include<stdio.h>
#include<stdbool.h>
#include "table_gen.h"
#define size 120

void movMat(bool a[size][size], bool b[size][size], int n);
void moltMat(bool a[size][size], bool b[size][size], bool c[size][size], int n);
int Identity_matrix_check(bool r[size][size], int n);
int invert(bool A[size][size], int N);
void matrix_gen(bool(*M)[Matrix_size], bool(*Inv_M)[Matrix_size], int n);
