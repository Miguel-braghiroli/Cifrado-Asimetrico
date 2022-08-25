package java_cryptography;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;

public class Asimetrico{
    private static final String RSA = "RSA";
    private static Scanner sc;

    public static KeyPair generateRSAKkeyPair() throws Exception{
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);

        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] do_RSAEncriptado(String texto, PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(texto.getBytes());
    }

    public static String do_RSADescripcion(byte[] cipherText, PublicKey publicKey) throws Exception{
        Cipher cipher = Cipher.getInstance(RSA);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] result = cipher.doFinal(cipherText);

        return new String(result);
    }

    public static void main(String args[]) throws Exception{
        KeyPair keypair = generateRSAKkeyPair();
        String texto = "Este es el texto " + "que quiero encriptar usandi RSA";
        byte[] cipherText = do_RSAEncriptado(texto, keypair.getPrivate());

        System.out.println("La Llave Publica es: " + DatatypeConverter.printHexBinary(keypair.getPublic().getEncoded()));
        System.out.println("La Llave Privada es: " + DatatypeConverter.printHexBinary(keypair.getPrivate().getEncoded()));

        System.out.println("El Texto Encriptado es: ");
        System.out.println(DatatypeConverter.printHexBinary(cipherText));

        String textoDescifrado = do_RSADescifrado(cipherText, keypair.getPublic());
        System.out.println("El Texto Descifrado es: " + textoDescifrado);
    }
}