#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define N 256

__attribute__((noinline))
void matmul(const double A[N][N], const double B[N][N], double C[N][N]) {
    for (int i = 0; i < N; i++) {
        for (int k = 0; k < N; k++) {
            double r = A[i][k];
            for (int j = 0; j < N; j++) {
                C[i][j] += r * B[k][j];
            }
        }
    }
}

int main(void) {
    static double A[N][N];
    static double B[N][N];
    static double C[N][N];

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            A[i][j] = (double)(i + j) * 0.01;
            B[i][j] = (double)(i - j) * 0.01;
            C[i][j] = 0.0;
        }
    }

    clock_t start = clock();
    matmul(A, B, C);
    clock_t end = clock();

    double checksum = 0.0;
    for (int i = 0; i < N; i++) {
        checksum += C[i][i];
    }

    double elapsed_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("{\"benchmark\":\"MatMul\",\"dim\":%d,\"time_ms\":%.2f,\"checksum\":%.2f}\n",
           N, elapsed_ms, checksum);
    return 0;
}
