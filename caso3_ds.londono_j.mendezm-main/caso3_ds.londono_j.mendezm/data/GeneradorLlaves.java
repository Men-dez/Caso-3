import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Properties;

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
 * Clase que se encarga de generar las llaves de cifrado (simétricas y asimétricas).
 */ 
 public class GeneradorLlaves {

    /* ****************************************************************
    * 			Constantes
    *****************************************************************/

    /**
     * Representa la ruta a guardar las llaves de cifrado.
     */
    private final static String PATH = "./data/keys";

    /**
     * Representa el cifrado simétrico
     */
    private final static int CIFRADO_SIMETRICO = 0; 

    /**
     * Representa el cifrado asimétrico
     */
    private final static int CIFRADO_ASIMETRICO = 1; 

    /**
     * Representa el algoritmo de cifrado asimétrico a implementar. 
     */
    private final static String ALGORITMO_ASIMETRICO = "RSA";

    /**
     * Representa el algoritmo de cifrado simétrico a implementar. 
     */
    private final static String ALGORITMO_SIMETRICO = "AES";

    /* ****************************************************************
    * 			Atributos
    *****************************************************************/

    /**
     * Representa el tipo de cifrado (simétrico o asimétric)
     */
    private int cifrado; 

    /**
     * Representa el número de clientes en la aplicación 
     */
    private int numClientes; 

    /* ****************************************************************
    * 			Constructor
    *****************************************************************/

    /**
     * Constructor de la clase Generador de llaves.
     * @param cifrado Tipo de cifrado.
     * @param numClientes Número de clientes. 
     */
    public GeneradorLlaves( int cifrado, int numClientes){
        this.cifrado = cifrado; 
        this.numClientes = numClientes; 
        preInit(PATH);
        init();
    }

    /* ****************************************************************
    * 			Métodos
    *****************************************************************/

    /**
     * Se encarga de limpiar la carpeta de llaves de cifrado (keys))
     * @param filepath Ruta a ser limpiada
     */
    public void preInit(String filepath){
        File f = new File (filepath);
        if(f.exists() && f.isDirectory()) {
            if (f.listFiles (). length == 0) {
				f.delete();
			 } else {
				File delFile[] = f.listFiles();
				int i = f.listFiles().length;
				for (int j = 0; j < i; j++) {
					if (delFile[j].isDirectory()) {
						 preInit (delFile [j] .getAbsolutePath ()); 
					}
					 delFile [j] .delete (); // eliminar un archivo
				}
            }
        }
    }

    /**
     * Se encarga de crear las llaves de cifrado (asimétricas o simétricas) de la aplicación. 
     */
    public void init(){
        File keys = new File("./data/keys");
        keys.mkdirs();
        if(cifrado == CIFRADO_SIMETRICO ) generarLlavesSimetrico();
        else generarLlavesAsimetrico();
    }

    /**
     * Se encarga de crear las llaves de cifrado simétrico
     */
    public void generarLlavesSimetrico(){
        for(int i=0; i<numClientes; i++){
            generarLlaveSimetricaCliente2Repetidor(i);
        }
        generarLlaveSimetricaRepetidor2Servidor();
    }

    /**
     * Se encarga de crear las llaves de cifrado asimétrico
     */
    public void generarLlavesAsimetrico(){
        for(int i=0; i<numClientes; i++){
            generarLlavesAsimetricasCliente(i);
        }
        generarLlavesAsimetricasRepetidor();
        generarLlavesAsimetricasServidor();
    }

    /**
     * Se encarga de generar la llave simétrica del Cliente -   Repetidor
     * @param id Id del cliente. 
.     */
    public void generarLlaveSimetricaCliente2Repetidor(int id){
        SecretKey secretKey = null; 

        try {
            KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO_SIMETRICO);
            secretKey = keygen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Base64.Encoder encoder = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_CR"+id+".txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoder.encodeToString(secretKey.getEncoded()));  
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Se encarga de generar la llave simétrica del Repetidor - Servidor
.     */
    public void generarLlaveSimetricaRepetidor2Servidor(){
        SecretKey secretKey = null; 

        try {
            KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO_SIMETRICO);
            secretKey = keygen.generateKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

        Base64.Encoder encoder = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_RS.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoder.encodeToString(secretKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Se encarga de generar el par de llaves asimétricas del Servidor.  
     */
    public void generarLlavesAsimetricasServidor(){
        PublicKey publicKey = null; 
        PrivateKey privateKey = null;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITMO_ASIMETRICO);
            keyPairGenerator.initialize(1024);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();   
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        Base64.Encoder encoderPrivate = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_S-.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPrivate.encodeToString(privateKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Base64.Encoder encoderPublic = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_S+.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPublic.encodeToString(publicKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Se encarga de generar el par de llaves asimétricas del Repetidor.  
     */
    public void generarLlavesAsimetricasRepetidor(){
        PublicKey publicKey = null; 
        PrivateKey privateKey = null;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITMO_ASIMETRICO);
            keyPairGenerator.initialize(1024);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();   
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        Base64.Encoder encoderPrivate = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_R-.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPrivate.encodeToString(privateKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Base64.Encoder encoderPublic = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_R+.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPublic.encodeToString(publicKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Se encarga de generar el par de llaves asimétricas del Cliente.  
     * @param id Id del cliente. 
     */
    public void generarLlavesAsimetricasCliente(int id){
        PublicKey publicKey = null; 
        PrivateKey privateKey = null;

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITMO_ASIMETRICO);
            keyPairGenerator.initialize(1024);

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();   
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        
        Base64.Encoder encoderPrivate = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_C"+id+"-.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPrivate.encodeToString(privateKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }

        Base64.Encoder encoderPublic = Base64.getEncoder();

        try(FileWriter fw = new FileWriter("./data/keys/K_C"+id+"+.txt")){
            PrintWriter  pw = new PrintWriter(fw);
            pw.write(encoderPublic.encodeToString(publicKey.getEncoded()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    /* ****************************************************************
    * 			Main
    *****************************************************************/

    public static void main(String[] args) {
        Properties properties = new Properties();
        
        try{
            properties.load(new FileInputStream( new File("./config.properties") ));
            int cifrado = Integer.parseInt(properties.getProperty("Cifrado"));
            int numClientes = Integer.parseInt(properties.getProperty("NumClientes"));
            GeneradorLlaves generadorLlaves = new GeneradorLlaves(cifrado, numClientes);

        }catch(Exception e){
            e.printStackTrace();
        }
    }
 }
