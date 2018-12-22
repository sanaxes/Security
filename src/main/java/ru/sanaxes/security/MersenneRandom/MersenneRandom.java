package ru.sanaxes.security.MersenneRandom;

/**
 * ГПСЧ Вихрь Мерсенна
 */
public class MersenneRandom {

    /**
     * Размер байтового пула
     */
    private static final int N = 624;

    /**
     * Второй параметр
     */
    private static final int M = 397;

    /**
     * Исходная матрица
     */
    private static final int[] matrix = {0x0, 0x9908b0df};

    /**
     * Байтовый пул
     */
    private int[] bytePull;

    /**
     * Текущий индекс в байтовом пулу
     */
    private int index;

    /**
     * Конструктор по умолчанию задает порождающий элемент в качестве текущего системного времени
     */
    public MersenneRandom() {
        bytePull = new int[N];
        setSeed((int) System.currentTimeMillis());
    }

    /**
     * Конструктор с параметром int котоырй используется в качестве порождающего элемента
     */
    public MersenneRandom(int seed) {
        bytePull = new int[N];
        setSeed(seed);
    }

    /**
     * Устновить порождающей элемент
     */
    public void setSeed(int seed) {
        long longSeed = seed;
        bytePull[0] = (int) longSeed;
        for (index = 1; index < N; ++index) {
            longSeed = (1812433253l * (longSeed ^ (longSeed >> 30)) + index) & 0xffffffffL;
            bytePull[index] = (int) longSeed;
        }
    }

    /**
     * Генерирует псевдослучайное число по заданному алгоритму
     */
    private int next(int bits) {
        int indexY;
        if (index >= N) {
            int next = bytePull[0];
            for (int k = 0; k < N - M; ++k) {
                int current = next;
                next = bytePull[k + 1];
                indexY = (current & 0x80000000) | (next & 0x7fffffff);
                bytePull[k] = bytePull[k + M] ^ (indexY >>> 1) ^ matrix[indexY & 0x1];
            }
            for (int k = N - M; k < N - 1; ++k) {
                int current = next;
                next = bytePull[k + 1];
                indexY = (current & 0x80000000) | (next & 0x7fffffff);
                bytePull[k] = bytePull[k + (M - N)] ^ (indexY >>> 1) ^ matrix[indexY & 0x1];
            }
            indexY = (next & 0x80000000) | (bytePull[0] & 0x7fffffff);
            bytePull[N - 1] = bytePull[M - 1] ^ (indexY >>> 1) ^ matrix[indexY & 0x1];
            index = 0;
        }
        indexY = bytePull[index++];
        indexY ^= indexY >>> 11;
        indexY ^= (indexY << 7) & 0x9d2c5680;
        indexY ^= (indexY << 15) & 0xefc60000;
        indexY ^= indexY >>> 18;
        return indexY >>> (32 - bits);

    }

    /**
     * Генерирует случайное цело int число
     */
    public int nextInt() {
        return next(32);
    }

    /**
     * Генерирует случайный long
     */
    public long nextLong() {
        final long high = ((long) next(32)) << 32;
        final long low = ((long) next(32)) & 0xffffffffL;
        return high | low;
    }

    /**
     * Генерирует случайный double
     */
    public double nextDouble() {
        final long high = ((long) next(26)) << 26;
        final int low = next(26);
        return (high | low) * 0x1.0p-52d;
    }

}