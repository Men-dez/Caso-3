import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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
    * Clase que representa el repetidor de la aplicación
     */
    public class Repetidor {

    /* ****************************************************************
    * 			Constantes Opcionales (Cifrado Simétrico)
    *****************************************************************/

    /**
     * Llave de cifrado Repetidor2Servidor
     */
    public final static int KEY_REPETIDOR2SERVIDOR = 0;

    /**
     * Inicio de llaves de cifrado Cliente2Repetidor 
     */
    public final static int BEGIN_KEYS_CLIENTE2REPETIDOR = 1;

    /* ****************************************************************
    * 			Constantes Opcionales (Cifrado Asimétrico)
    *****************************************************************/    

    /**
     * Llave de cifrado privada Repetidor.
     */
    public final static int KEY_REPETIDOR_PRIVADA = 0;

    /**
     * Llave de cifrado pública Repetidor.
     */
    public final static int KEY_CLIENTE_PUBLICA = 1; 

    /**
     * Llave de cifrado pública Servidor.
     */
    public final static int KEY_SERVIDOR_PUBLICA = 2; 

    /**
     * Inicio de llaves de cifrado públicas de clientes
     */
    public final static int BEGIN_KEYS_CLIENTES_PUBLICAS = 3; 
    
    /* ****************************************************************
    * 			Constantes
    *****************************************************************/
   
    /**
     * Representa el cifrado Simétrico.
     */
    public final static int CIFRADO_SIMETRICO = 0; 

    /**
     * Representa el cifrado Asimétrico.
     */
    public final static int CIFRADO_ASIMETRICO = 1; 

    /**
     * Puerto de la conexión
     */
    public final static int PUERTO = 5678; 

    /* ****************************************************************
    * 			Atributos
    *****************************************************************/    

    /**
     * Representa el tipo de cifrado
     * 0 -> Cifrado simétrico
     * 1 -> Cifrado asimétrico 
     */
    private int cifrado;     

    /**
     * Representa el número de clientes en la aplicación 
     */
    private int numClientes; 

    /**
     * Representa una lista de las llaves de cifrado (ya sea simétrico o asimétrico). 
     */
    private static ArrayList<Object> llavesCifrado; 

    /* ****************************************************************
    * 			Contructor
    *****************************************************************/
    /**
     * Constructor de la clase Servidor
     * @param cifrado Tipo de cifrado.
     * @param numClientes Número de clientes. 
     */
    public Repetidor(int cifrado, int numClientes){
        this.cifrado = cifrado;  
        this.numClientes = numClientes;
        llavesCifrado = new ArrayList<Object>();
        preInit();
        init();
    }

    /* ****************************************************************
    * 			Sets and Gets
    *****************************************************************/

    /**
     * Se encarga de retornar el tipo de cifrado. 
     * @return Tipo de cifrado. 
     */
    public int getCifrado(){
        return cifrado;
    }
    
    /**
     * Se encarga de retornar el número de clientes en la aplicación.
     * @return Numero de clientes. 
     */
    public int getNumClientes(){
        return numClientes; 
    }
    
    /**
     * Se encarga de retornar el arreglo de llaves de cifrado del Servidor.
     * @return Arreglo de llaves de cifrado del Servidor.
     */
    public ArrayList<Object> getLlavesCifrado(){
        return llavesCifrado; 
    } 

   /* ****************************************************************
    * 			Métodos
    *****************************************************************/
    
    /**
     * Se encarga de cargar las llaves en función del tipo de cifrado.
     */
    public void preInit(){
        if(cifrado == CIFRADO_SIMETRICO){
            cargarLlaveSimetrica("K_RS");
            for(int i=0; i<numClientes; i++){
                cargarLlaveSimetrica("K_CR"+i);
            }
        }
        else{
            cargarLlavePrivada("K_R-");
            cargarLlavesPublicas("K_R+");
            cargarLlavesPublicas("K_S+");
            for(int i=0; i<numClientes; i++){
                cargarLlavesPublicas("K_C"+i+"+");
            }
        }
    }

    /**
     * Se encarga de cargar una llave simétrica dada por parámetro.
     * @param llave Llave simétrica a ser cargada
     */
    public void cargarLlaveSimetrica(String llave){
        try {
            File llaveSimetrica = new File("./data/keys/"+llave+".txt");   
            FileReader fr = new FileReader (llaveSimetrica);
            BufferedReader br = new BufferedReader(fr);
            String keyContent = br.readLine();

            byte[] keyDecoded= Base64.getDecoder().decode(keyContent);
            SecretKey secretKey = new SecretKeySpec(keyDecoded, 0, keyDecoded.length, "AES");
            llavesCifrado.add(secretKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Se encarga de cargar una llave asimétrica privada dada por parámetro.
     * @param llave Llave asimétrica privada a ser cargada.
     */
    public void cargarLlavePrivada(String llave){
        try{
            File llavePrivada = new File("./data/keys/"+llave+".txt");
            FileReader fr = new FileReader(llavePrivada);
            BufferedReader br = new BufferedReader(fr);
            String privateKeyContent = br.readLine();
            
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] privateKeyDecoded = Base64.getDecoder().decode(privateKeyContent);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyDecoded);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            llavesCifrado.add(privateKey);
        } catch(InvalidKeySpecException e){
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }

    /**
     * Se encarga de cargar una llave asimétrica pública dada por parámetro.
     * @param llave Llave asimétrica pública a ser cargada.
     */
    public void cargarLlavesPublicas(String llave){
        try{
            File llave_Publica = new File("./data/keys/"+llave+".txt");
            FileReader fr = new FileReader(llave_Publica);
            BufferedReader br = new BufferedReader(fr);
            String publicKeyContent = br.readLine();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] publicKeyDecoded = Base64.getDecoder().decode(publicKeyContent);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyDecoded);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            llavesCifrado.add(publicKey);
        } catch(InvalidKeySpecException e){
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }
    }    

    /**
     * Inicializa el Repetidor
     */
    public void init(){
        ServerSocket serverSocket = null; 
        try{
            serverSocket = new ServerSocket(PUERTO); 
            System.out.println("Repetidor iniciado...");

            while(true){
                Socket cliente = serverSocket.accept(); 
 
                RepetidorDelegado repetidorDelegado = new RepetidorDelegado(this, cliente); 
                repetidorDelegado.start();
            }

        }
        catch(Exception e){
            System.out.println(e.getMessage());
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
            Repetidor repetidor = new Repetidor(cifrado, numClientes); 
        }catch(Exception e){
            e.printStackTrace();
        }
    }
 }