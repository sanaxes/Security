package ru.sanaxes.security;

import ru.sanaxes.security.Magma.Magma;
import ru.sanaxes.security.Magma.MagmaMode;
import ru.sanaxes.security.MersenneRandom.MersenneRandom;
import ru.sanaxes.security.Streebog.StreebogHash;
import ru.sanaxes.security.Streebog.StreebogHashSize;

import java.io.*;
import java.nio.file.Paths;

/**
 * Исполняемый класс для проверки написанных алгоритмов
 */
public class InformationSecurityApplication {

    private static final String originalFilePath = System.getProperty("user.home") + "/security/src/main/resources/original.txt";
    private static final String encryptedFilePath = System.getProperty("user.home") + "/security/src/main/resources/encrypted.txt";
    private static final String decryptedFilePath = System.getProperty("user.home") + "/security/src/main/resources/decrypted.txt";

    public static void main(String[] args) throws Exception {
        // Вихрь мерсенна
        MersenneRandom random = new MersenneRandom();
        for (int i = 0; i < 3; i++) {
            System.out.println("integer\t" + "double\t" + "long");
            System.out.println(random.nextInt() + "\t" + random.nextDouble() + "\t" + random.nextLong());
        }
        // Магма
        DataInputStream dis = new DataInputStream(new FileInputStream(originalFilePath));
        DataOutputStream dos = new DataOutputStream(new FileOutputStream(encryptedFilePath));
        Magma magma = new Magma();
        magma.process(MagmaMode.ENCRYPT, dos, dis);
        dis = new DataInputStream(new FileInputStream(encryptedFilePath));
        dos = new DataOutputStream(new FileOutputStream(decryptedFilePath));
        magma.process(MagmaMode.DECRYPT, dos, dis);
        // Стрибог
        StreebogHash streebogHash = new StreebogHash(StreebogHashSize.STREEBOG_256);
        String example = "210987654321098765432109876543210987654321098765432109876543210";
        byte[] bytes = example.getBytes();
        int[] message = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            message[i] = bytes[i];
        }
        int[] result = streebogHash.getHashFunction(message);
        String[] hexArray = new String[result.length];
        for (int i = 0; i < hexArray.length; i++) {
            hexArray[i] = String.format("%02X", result[i]);
        }
        String hexResult = "HEX: " + String.join("-", hexArray).toUpperCase();
        System.out.print(hexResult);
    }

}
