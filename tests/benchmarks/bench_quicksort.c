#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

void swap(int *a, int *b) {
    int t = *a;
    *a = *b;
    *b = t;
}

int partition(int arr[], int low, int high) {
    int pivot = arr[high];
    int i = (low - 1);
    for (int j = low; j <= high - 1; j++) {
        if (arr[j] < pivot) {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }
    swap(&arr[i + 1], &arr[high]);
    return (i + 1);
}

void quicksort(int arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quicksort(arr, low, pi - 1);
        quicksort(arr, pi + 1, high);
    }
}

int main(int argc, char **argv) {
    int n = 500000;
    if (argc > 1) n = atoi(argv[1]);

    int *arr = (int *)malloc(n * sizeof(int));
    if (!arr) return 1;

    // Fixed deterministic LCG pseudo-random sequence
    uint32_t seed = 1337;
    for (int i = 0; i < n; i++) {
        seed = seed * 1664525 + 1013904223;
        arr[i] = (int)(seed % 1000000);
    }

    clock_t start = clock();
    quicksort(arr, 0, n - 1);
    clock_t end = clock();

    // Verification
    int sorted = 1;
    for (int i = 1; i < n; i++) {
        if (arr[i] < arr[i - 1]) {
            sorted = 0;
            break;
        }
    }

    double elapsed_ms = ((double)(end - start) / CLOCKS_PER_SEC) * 1000.0;
    printf("{\"benchmark\":\"Quicksort\",\"elements\":%d,\"time_ms\":%.2f,\"sorted\":%d}\n",
           n, elapsed_ms, sorted);

    free(arr);
    return sorted ? 0 : 1;
}
