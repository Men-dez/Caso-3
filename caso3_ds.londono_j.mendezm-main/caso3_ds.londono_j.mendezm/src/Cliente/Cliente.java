import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
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
     * Clase que representa el cliente de la aplicación
     */
    public class Cliente extends Thread{

    /* ****************************************************************
    * 			Constantes Opcionales (Cifrado Simétrico)
    *****************************************************************/

    /**
     * Inicio de llaves de cifrado Cliente2Repetidor 
     */
    private final static int KEY_CLIENTE2REPETIDOR = 0;

    /* ****************************************************************
    * 			Constantes Opcionales (Cifrado Asimétrico)
    *****************************************************************/     

    /**
     * Llave de cifrado privada Cliente.
     */
    private final static int KEY_CLIENTE_PRIVADA = 0;

    /**
     * Llave de cifrado pública Servidor.
     */
    private final static int KEY_SERVIDOR_PUBLICA = 1; 

    /**
     * Llave de cifrado pública Repetidor.
     */
    private final static int KEY_REPETIDOR_PUBLICA = 2; 

    /**
     * Inicio de llaves de cifrado públicas de clientes
     */
    private final static int BEGIN_KEYS_CLIENTES_PUBLICAS = 3; 


    /* ****************************************************************
    * 			Constantes
    *****************************************************************/

    /**
     * Representa el cifrado Simétrico.
     */
    private final static int CIFRADO_SIMETRICO = 0; 

    /**
     * Representa el cifrado Asimétrico.
     */
    private final static int CIFRADO_ASIMETRICO = 1;     

    /**
     * Host local del cliente
     */
    private final static String HOST = "192.168.0.9";

    /**
     * Puerto de la conexión. 
     */
    private final static int PUERTO = 5678; 

    /* ****************************************************************
    * 			Atributos
    *****************************************************************/

    /**
     * Id del cliente
     */
    private int id; 

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
     * Identificación del mensaje a leer.
     */
    private String idMensaje; 

    /**
     * Socket del repetidor delegado.
     */
    private Socket repetidorDelegado; 

    /**
     * Medio de comunicación: Repetidor delegado -> Cliente.
     */
    private BufferedReader input; 

    /**
     * Medio de comunicación: Cliente -> Repetidor delegado . 
     */
    private PrintWriter output; 

    /**
     * Representa una lista de las llaves de cifrado (ya sea simétrico o asimétrico). 
     */
    private ArrayList<Object> llavesCifrado;     

    /* ****************************************************************
    * 			Constructor
    *****************************************************************/    

    public Cliente(int id, int cifrado, int numClientes, String idMensaje){
        this.id = id; 
        this.cifrado = cifrado; 
        this.numClientes = numClientes;
        this.idMensaje = idMensaje; 
        llavesCifrado = new ArrayList<Object>();
        preInit();
        init();
    }

    /* ****************************************************************
    * 			Sets and Gets
    *****************************************************************/

    /**
     * Se encarga de retornar el arreglo de llaves de cifrado de Cliente
     * @return Arreglo de llaves de cifrado de Cliente
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
            cargarLlaveSimetrica("K_CR"+id);
        }
        else{
            cargarLlavePrivada("K_C"+id+"-");
            cargarLlavesPublicas("K_S+");
            cargarLlavesPublicas("K_R+");
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
     * Inicializa el Cliente
     */
    public void init(){
        try{
            repetidorDelegado = new Socket(HOST, PUERTO);

            InputStream in = repetidorDelegado.getInputStream();
            OutputStream out = repetidorDelegado.getOutputStream();
            
            input = new BufferedReader(new InputStreamReader(in));
            output = new PrintWriter(new OutputStreamWriter(out));
        }
        catch(IOException e){
            e.printStackTrace();
        }
    }

    /* ****************************************************************
    * 			Cifrado
    *****************************************************************/

    /**
     * Se encarga del cifrado simétrico de la identificación del mensaje del cliente.
     * @return Arreglo de bytes de la dentificación del mensaje cifrado. 
     */
    public byte[] cifradoSimetricoMensaje(){
        SecretKey Cliente2Repetidor = (SecretKey) llavesCifrado.get(KEY_CLIENTE2REPETIDOR);
        byte[] msjCifrado = Simetrico.cifrar(Cliente2Repetidor, idMensaje);
        return msjCifrado;
    }

    /**
     * Se encarga del cifrado asimétrico de la identificación del mensaje del cliente 
     * @return Arreglo de bytes de la dentificación del mensaje cifrado.
     */
    public byte[] cifradoAsimetricoMensaje(){
        PublicKey keyRepetidorPublica = (PublicKey) llavesCifrado.get(KEY_REPETIDOR_PUBLICA);
        byte [] msjCifrado = Asimetrico.cifrar( keyRepetidorPublica, idMensaje);
        return msjCifrado;
    }

    /* ****************************************************************
    * 			Descifrado
    *****************************************************************/

    /**
     * Se encarga del descifrado simétrico del mensaje del cliente.
     * @param idCliente mensaje del cliente.
     * @param idMsjCifradoRepetidor Mensaje a descifrar.
     * @return Arreglo de bytes del mensaje descifrado.
     */
    public byte[] descifradoSimetricoMensaje(String idMsjCifradoRepetidor){
        SecretKey repetidor2Repetidor = (SecretKey) llavesCifrado.get(KEY_CLIENTE2REPETIDOR);
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoRepetidor);
        byte[] idMsjDescifrado = Simetrico.descifrar( repetidor2Repetidor, bytes);
        return idMsjDescifrado;  
    }
    
    /**
     * Se encarga del descifrado asimétrico del mensaje del repetidor.
     * @param idMsjCifradoRepetidor Identificación del mensaje a descifrar.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoAsimetricoMensaje(String idMsjCifradoRepetidor){
        PrivateKey keyRepetidorPrivada = (PrivateKey) llavesCifrado.get(KEY_CLIENTE_PRIVADA);
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoRepetidor);
        byte[] idMsjDescifrado = Asimetrico.descifrar( keyRepetidorPrivada, bytes);
        return idMsjDescifrado;
    }

    /* ****************************************************************
    * 			Run
    *****************************************************************/    

    @Override
    public void run(){
        byte[] idMsjCifradoC2R=null;
        byte[] idMsjCifradoR2C=null;
        try{
            output.println("CLIENTE_"+id);
            output.flush();

            String ok = input.readLine();
            
            System.out.println( ok );
            System.out.println("Mensaje enviado:" + idMensaje);

            if(cifrado == CIFRADO_SIMETRICO){
                idMsjCifradoC2R = cifradoSimetricoMensaje();
            } 
            else idMsjCifradoC2R = cifradoAsimetricoMensaje();

            output.println( TransmisionBytes.byte2Str( idMsjCifradoC2R ) );
            output.flush();

            String mensaje = input.readLine();

            if(cifrado == CIFRADO_SIMETRICO){
                idMsjCifradoR2C = descifradoSimetricoMensaje(mensaje);
                System.out.println( "Mensaje: " + new String( idMsjCifradoR2C ) );
            } 
            else{
                idMsjCifradoR2C = descifradoAsimetricoMensaje(mensaje);
                System.out.println( "Mensaje: " + new String( idMsjCifradoR2C ));
            }

            repetidorDelegado.close();
        }
        catch(IOException e){
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

            for(int i=0; i<numClientes; i++){
                String idMensaje = "0"+Integer.toString((int) Math.floor( Math.random()*10 ));
                Cliente cliente = new Cliente(i, cifrado, numClientes ,idMensaje);
                cliente.start();
            }
            
        }catch(Exception e){
            e.printStackTrace();
        }
    }      
 }
