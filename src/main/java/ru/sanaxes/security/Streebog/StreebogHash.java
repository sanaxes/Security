package ru.sanaxes.security.Streebog;

/**
 * ГОСТ Р 34.11-2012 Хэш-функция Стрибог (256/512) бит
 */
public class StreebogHash {

    private int[] iv = new int[64];

    private StreebogHashSize hashSize;

    public StreebogHash(StreebogHashSize hashSize) {
        this.hashSize = hashSize;
        if (hashSize == StreebogHashSize.STREEBOG_512) {
            for (int i = 0; i < 64; i++) {
                iv[i] = 0x00;
            }
        } else if (hashSize == StreebogHashSize.STREEBOG_256) {
            for (int i = 0; i < 64; i++) {
                iv[i] = 0x01;
            }
        }
    }

    /**
     * Сложение по модулю
     */
    private int[] add(int[] a, int[] b) {
        int[] result = new int[a.length];
        int r = 0;
        for (int i = a.length - 1; i >= 0; i--) {
            result[i] = (a[i] + b[i] + r) & 0xFF;
            r = ((a[i] + b[i]) >> 8) & 0xFF;
        }
        return result;
    }

    /**
     * Исключающее ИЛИ
     */
    private int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    /**
     * S преобразование
     * Каждый байт из 512-битной входной последовательности
     * заменяется соответствующим байтом из таблицы подстановок {@link StreebogValues#sBox}
     */
    private int[] S(int[] state) {
        int[] result = new int[64];
        for (int i = 0; i < 64; i++) {
            result[i] = StreebogValues.sBox[state[i]];
        }
        return result;
    }

    /**
     * P преобразование
     * Для каждой пары байт из входной последовательности
     * происходит замена одного байта другим байтом из таблицы подставновок {@link StreebogValues#tBox}
     */
    private int[] P(int[] state) {
        int[] result = new int[64];
        for (int i = 0; i < 64; i++) {
            result[i] = state[StreebogValues.tBox[i]];
        }
        return result;
    }

    /**
     * L преобразование
     * Умножение 64-битного входного вектора на бинарную матрицу A размерами 64x64
     */
    private int[] L(int[] state) {
        int[] result = new int[64];
        for (int i = 0; i < 8; i++) {
            int[] v = new int[8];
            for (int k = 0; k < 8; k++) {
                for (int j = 0; j < 8; j++) {
                    if ((state[i * 8 + k] & (1 << (7 - j))) != 0) {
                        v = xor(v, StreebogValues.A[k * 8 + j]);
                    }
                }
            }
            System.arraycopy(v, 0, result, i * 8, 8);
        }
        return result;
    }

    /**
     * Формирование временного ключа K на кадлом раунде функции E {@link #E(int[], int[])}
     */
    private int[] KeySchedule(int[] K, int i) {
        K = xor(K, StreebogValues.C[i]);
        K = S(K);
        K = P(K);
        K = L(K);
        return K;
    }

    private int[] E(int[] K, int[] m) {
        int[] state = xor(K, m);
        for (int i = 0; i < 12; i++) {
            state = S(state);
            state = P(state);
            state = L(state);
            K = KeySchedule(K, i);
            state = xor(state, K);
        }
        return state;
    }

    /**
     * Функция сжатия
     */
    private int[] gN(int[] N, int[] h, int[] m) {
        int[] K = xor(h, N);
        K = S(K);
        K = P(K);
        K = L(K);
        int[] t = E(K, m);
        t = xor(t, h);
        return xor(t, m);
    }

    /**
     * Вычисление хэш-функции
     */
    public int[] getHashFunction(int[] message) {
        int[] h = new int[64];
        System.arraycopy(iv, 0, h, 0, 64);
        int[] M = new int[message.length];
        System.arraycopy(message, 0, M, 0, message.length);
        int[] N = new int[64];
        int[] sigma = new int[64];
        int[] m = new int[64];
        int l = message.length;
        while (l >= 64) {
            System.arraycopy(M, l - 64, m, 0, 64);
            h = gN(N, h, m);
            N = add(N, StreebogValues.bv512);
            sigma = add(sigma, m);
            l -= 64;
        }
        for (int i = 0; i < 63 - l; i++) {
            m[i] = 0;
        }
        m[63 - l] = 0x01;
        if (l > 0) {
            System.arraycopy(M, 0, m, 63 - l + 1, l);
        }
        h = gN(N, h, m);
        int[] bv = new int[64];
        bv[62] = (l * 8) >> 8;
        bv[63] = (l * 8) & 0xFF;
        N = add(N, bv);
        sigma = add(sigma, m);
        h = gN(StreebogValues.bv00, h, N);
        h = gN(StreebogValues.bv00, h, sigma);
        if (hashSize == StreebogHashSize.STREEBOG_512) {
            return h;
        } else {
            int[] h256 = new int[32];
            System.arraycopy(h, 0, h256, 0, 32);
            return h256;
        }
    }
}
