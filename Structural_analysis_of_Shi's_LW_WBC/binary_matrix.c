#include "binary_matrix.h"
#include "table_gen.h"

void movMat(bool a[size][size], bool b[size][size], int n) {

    int i, j;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++)
            b[i][j] = a[i][j];

}

void moltMat(bool a[size][size], bool b[size][size], bool c[size][size], int n) {
    // c = a * b

    int i, j, x;
    for (i = 0; i < n; i++)
        for (j = 0; j < n; j++) {
            c[i][j] = 0x0;
            for (x = 0; x < n; x++)
                c[i][j] ^= a[i][x] & b[x][j];
        }


}

int Identity_matrix_check(bool r[size][size], int n) {

    int i, j;
    int return_value = 0;
    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            if (i == j) {
                if (r[i][j] != 1)
                    return_value = 1;
            }
            else {
                if (r[i][j] != 0)
                    return_value = 1;
            }
        }
    }

    return return_value;
}

int invert(bool A[size][size], int N) {

    int k, i, x, j, t;

    for (k = 0; k < N; k++) {
        if (A[k][k] == 0) {
            for (i = k; i < N; ++i) {
                if (A[i][k] != 0) {
                    for (x = 0; x < 2 * N; x++) {
                        t = A[k][x];
                        A[k][x] = A[i][x];
                        A[i][x] = t;
                    }
                }
            }
            if (A[k][k] == 0) {
                return 0;
            }
        }

        for (i = 0; i < N; ++i) {
            if (i != k) {
                if (A[i][k]) {
                    for (j = k; j < 2 * N; ++j) {
                        A[i][j] = A[i][j] ^ A[k][j];
                    }
                }
            }
        }

    }

    return 1;
}

void matrix_gen(bool(*M)[Matrix_size], bool(*Inv_M)[Matrix_size], int n) {

    bool a[size][size] = { 0 };
    bool b[size][size] = { 0 };
    bool r[size][size] = { 0 };

    int i, j;

    while (1)
    {
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < n; j++) {
                a[i][j] = rand() % 2;
            }
        }
        movMat(a, b, n);

        for (i = 0; i < n; i++)
            for (j = 0; j < 2 * n; j++)
                if (j == (i + n))
                    a[i][j] = 1;

        invert(a, n);

        for (i = 0; i < n; i++)
            for (j = 0; j < n; j++)
                a[i][j] = a[i][j + n];

        moltMat(a, b, r, n);

        if (0 == Identity_matrix_check(r, n))
            break;

        for (int i = 0; i < n; i++) {
            memset(a[i], 0, sizeof(bool) * size);
        }
    }

    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
            M[i][j] = b[i][j];
            Inv_M[i][j] = a[i][j];
        }
    }
}