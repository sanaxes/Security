package ru.sanaxes.security.Magma;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;

/**
 * ГОСТ 28147-89 Магма (В режиме простой замены)
 */
public class Magma {

    private final static byte table[][] = {
            {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
            {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
            {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
            {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
            {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
            {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
            {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
            {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
    };

    /**
     * Ключ по умолчанию
     */
    private byte key[][] = new byte[8][4];

    /**
     * Карта ключей
     */
    private final static int[] keyMap = {
            0, 1, 2, 3, 4, 5, 6, 7,
            0, 1, 2, 3, 4, 5, 6, 7,
            0, 1, 2, 3, 4, 5, 6, 7,
            7, 6, 5, 4, 3, 2, 1, 0
    };

    /**
     * Алгоритм шифровки-дешифровки в зависимости от режима {@link MagmaMode}
     *
     * @param mode         - режим (Шифровка/Дешифровка)
     * @param outputStream - выходной поток в который происходит запись
     * @param inputStream  - входной потом из которого берутся данные
     */
    public void process(MagmaMode mode, DataOutputStream outputStream, DataInputStream inputStream) throws Exception {
        byte[] data = new byte[8];
        int count = inputStream.read(data);
        while (count != -1) {
            if (count % 8 > 0) {
                for (int i = count; i < 8; i++) {
                    data[i] = 0;
                }
            }
            byte[] B = new byte[4];
            byte[] A = new byte[4];
            System.arraycopy(data, 0, B, 0, 4);
            System.arraycopy(data, 4, A, 0, 4);
            for (int i = 0; i < 32; i++) {
                byte[] K;
                switch (mode) {
                    case ENCRYPT:
                        K = key[keyMap[i]];
                        break;
                    case DECRYPT:
                        K = key[keyMap[31 - i]];
                        break;
                    default:
                        throw new NullPointerException("Режим шифрования не может быть null!");
                }
                int buffer = ByteBuffer.wrap(A).getInt() + ByteBuffer.wrap(K).getInt();
                buffer &= 0xffffffff;
                // t Преобразование
                int[] s = {
                        (buffer & 0xF0000000) >>> 28,
                        (buffer & 0x0F000000) >>> 24,
                        (buffer & 0x00F00000) >>> 20,
                        (buffer & 0x000F0000) >>> 16,
                        (buffer & 0x0000F000) >>> 12,
                        (buffer & 0x00000F00) >>> 8,
                        (buffer & 0x000000F0) >>> 4,
                        (buffer & 0x0000000F)
                };
                buffer = 0x00000000;
                for (int b = 0; b < 8; b++) {
                    buffer <<= 4;
                    buffer += table[b][s[b] & 0x0000000f];
                }
                buffer = ((buffer << 11) | (buffer >>> 21 & 0x000007FF));
                // ..
                byte[] resBytes = ByteBuffer.allocate(4).putInt(buffer).array();
                byte[] newB = {0x00, 0x00, 0x00, 0x00};
                System.arraycopy(A, 0, newB, 0, 4);
                for (int b = 0; b < 4; b++) {
                    A[b] = (byte) (resBytes[b] ^ B[b]);
                }
                System.arraycopy(newB, 0, B, 0, 4);
            }
            outputStream.write(A, 0, A.length);
            outputStream.write(B, 0, B.length);
            count = inputStream.read(data);
        }
        inputStream.close();
        outputStream.close();
    }

    /**
     * Установить ключ
     *
     * @param key - ключ
     */
    public void setKey(byte[][] key) {
        this.key = key;
    }

    /**
     * @return Ключ
     */
    public byte[][] getKey() {
        return this.key;
    }
}