    import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

    /**~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     * Universidad	de	los	Andes	(Bogotá	- Colombia)
     * Departamento	de	Ingeniería	de	Sistemas	y	Computación
     * Licenciado	bajo	el	esquema	Academic Free License versión 2.1
     * 		
     * Curso: isis2203 -  Infrastructura Computacional
     * Proyecto: Seguridad
     * @version 1.0
     * @author 
     * Octubre de 2021
     * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     */

    /**
     * Clase que representa el algoritmo de cifrado Simétrico. 
     */
    public class Simetrico{

   /* ****************************************************************
    * 			Constantes
    *****************************************************************/

    /**
     * Mecanimos de padding a utilizar para cifrar y descifrar.
     * AES, modo ECB, esquema de relleno PKCS5, llave de 128 bits.
     */
    private final static String PADDING = "AES/ECB/PKCS5Padding"; 

   /* ****************************************************************
    * 			Métodos
    *****************************************************************/

    /**
     * Se encarga de cifrar un mensaje con difrado Simétrico dado una llave secreta. 
     * @param llave Llave para cifrar el mensaje.
     * @param texto Mensaje a cifrar. 
     * @return Mensaje cifrado en una arreglo de bytes
     */
    public static byte[] cifrar(SecretKey llave, String texto){
        byte[] textoCifrado; 
        try{
            Cipher cifrador = Cipher.getInstance(PADDING);
            byte[] textoClaro = texto.getBytes(); 

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado; 
        }
        catch(Exception e){
            System.out.println("Excepción; " + e.getMessage());
            return  null;  
        }
    }
    
    /**
     * Se encarga de descifrar un mensaje con difrado Simétrico dado su representación en bytes y la llave secreta
     * @param llave Llave para descifrar el mensaje. 
     * @param texto Mensaje en bytes a descifrar.
     * @return Mensaje descifrado en una arreglo de bytes
     */
    public static byte[] descifrar(SecretKey llave, byte[] texto){
        byte[] textoClaro; 

        try{
            Cipher cifrador = Cipher.getInstance(PADDING);

            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro =  cifrador.doFinal(texto);
            
            return textoClaro;  
        }
        catch(Exception e){
            System.out.println("Excepción: " + e.getMessage());
            return null; 
        }
    }

 }