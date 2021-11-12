    import java.security.Key;
    import javax.crypto.Cipher;

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
     * Clase que representa el algoritmo de cifrado Asimétrico. 
     */
    public class Asimetrico{

   /* ****************************************************************
    * 			Constantes
    *****************************************************************/
    
    /**
     * Representa el algoritmo de Cifrado Asimétrico.
     */
    private final static String ALGORITMO = "RSA";

   /* ****************************************************************
    * 			Métodos
    *****************************************************************/
    
    /**
     * Se encarga de cifrar un mensaje con difrado Asimétrico dada una llave y un algoritmo. 
     * @param llave Llave para cifrar el mensaje.
     * @param texto Mensaje a cifrar. 
     * @return Mensaje cifrado en una arreglo de bytes
     */
    public static byte[] cifrar(Key llave, String texto){
        byte[] textoCifrado; 
        
        try{
            Cipher cifrador = Cipher.getInstance(ALGORITMO);
            byte[] textoClaro = texto.getBytes(); 

            cifrador.init(Cipher.ENCRYPT_MODE, llave);
            textoCifrado = cifrador.doFinal(textoClaro);

            return textoCifrado;
        } catch(Exception e){
            System.out.println("Excepción: " + e.getMessage());
            return null; 
        }
    } 

    /**
     * Se encarga de descifrar un mensaje en representación de bytes con cifrado Asimétrico dada una llave y un algoritmo. 
     * @param llave Llave para descifrar el mensaje.
     * @param algoritmo Algoritmo para descifrar el mensaje. 
     * @param texto Texto en bytes a descifrar.
     * @return Mensaje descifrado en una arreglo de bytes.
     */
    public static byte[] descifrar(Key llave,byte[] texto){
        byte[] textoClaro; 

        try{
            Cipher cifrador = Cipher.getInstance(ALGORITMO);
            cifrador.init(Cipher.DECRYPT_MODE, llave);
            textoClaro = cifrador.doFinal(texto);
        } catch(Exception e){
            System.out.println("Excepción; " + e.getMessage());
            return null; 
        }

        return textoClaro;
    } 
 }