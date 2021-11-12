import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;

/**
 * Clase que representa el repetidor delegado de la aplicación
 */
 public class RepetidorDelegado extends Thread{

    /* ****************************************************************
    * 			Constantes
    *****************************************************************/
    /**
     * Host local del repetidor delegado
     */
    private final static String HOST = "192.168.0.9";

    /**
     * Puerto de la conexión. 
     */
    private final static int PUERTO = 1234; 

    /* ****************************************************************
    * 			Atributos
    *****************************************************************/

    /**
     * Representa una instancia de la clase Repetidor
     */
    private Repetidor repetidor; 

    /**
     * Socket del cliente a ser atentido.
     */
    private Socket cliente; 

    /**
     * Medio de comunicación: Cliente -> Repetidor delegado .
     */
    private BufferedReader inputCliente; 

    /**
     * Medio de comunicación: Repetidor delegado -> Cliente.  
     */
    private PrintWriter outputCliente; 

    /**
     * Socket del repetidor delegado.
     */
    private Socket servidorDelegado; 

    /**
     * Medio de comunicación: Servidor delegado -> Repetidor delegado .
     */
    private BufferedReader inputServidorDelegado; 

    /**
     * Medio de comunicación: Repetidor delegado -> Servidor delegado.  
     */
    private PrintWriter outputServidorDelegado; 
        
    /* ****************************************************************
    * 			Constructor
    *****************************************************************/   
    
    public RepetidorDelegado(Repetidor repetidor, Socket cliente){
        this.repetidor = repetidor;
        this.cliente = cliente; 
        System.out.println("Cliente conectado.");
        init1();
    }

    /**
     * Inicializa el Repetidor delegado (cliente).
     */
    public void init1(){
        try{
            InputStream in = cliente.getInputStream();
            OutputStream out = cliente.getOutputStream();

            inputCliente = new BufferedReader(new InputStreamReader(in));
            outputCliente = new PrintWriter(new OutputStreamWriter(out));
        }
        catch(IOException e){
            e.printStackTrace();
        } 
    }

    /**
     * Inicializa el Repetidor delegado (servidor).
     */
    public void init2(){
        try{
            servidorDelegado = new Socket(HOST, PUERTO);

            InputStream in = servidorDelegado.getInputStream();
            OutputStream out = servidorDelegado.getOutputStream();
            
            inputServidorDelegado = new BufferedReader(new InputStreamReader(in));
            outputServidorDelegado = new PrintWriter(new OutputStreamWriter(out));

        }catch(IOException e){
            e.printStackTrace();
        }
    }
  
    /* ****************************************************************
    * 			Descifrado simétrico (Cliente y Servidor)
    *****************************************************************/ 

    /**
     * Se encarga del descifrado simétrico de la identificación del mensaje del cliente.
     * @param idCliente Identificación del cliente.
     * @param idMsjCifradoCliente Identificación del mensaje a descifrar.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoSimetricoMensajeCliente(int idCliente, String idMsjCifradoCliente){

        SecretKey cliente2Repetidor = (SecretKey) repetidor.getLlavesCifrado().get(Repetidor.BEGIN_KEYS_CLIENTE2REPETIDOR+idCliente);
        System.out.println( idMsjCifradoCliente );
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoCliente);
        byte[] idMsjDescifrado = Simetrico.descifrar( cliente2Repetidor, bytes);
        return idMsjDescifrado;  
    }
    
    /**
     * Se encarga del descifrado simétrico de la identificación del mensaje del servidor.
     * @param idMsjCifradoCliente Identificación del mensaje a descifrar.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoSimetricoMensajeServidor(String idMsjCifradoCliente){
        SecretKey servidor2Repetidor = (SecretKey) repetidor.getLlavesCifrado().get(Repetidor.KEY_REPETIDOR2SERVIDOR);
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoCliente);
        byte[] idMsjDescifrado = Simetrico.descifrar( servidor2Repetidor, bytes);
        return idMsjDescifrado;  
    }

    /* ****************************************************************
    * 			Descifrado Asimétrico (Cliente y Servidor)
    *****************************************************************/ 

    /**
     * Se encarga del descifrado asimétrico de la identificación del mensaje del cliente.
     * @param idMsjCifradoCliente Identificación del mensaje a descifrar.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoAsimetricoMensaje(String idMsjCifradoCliente){
        PrivateKey keyRepetidorPrivada = (PrivateKey) repetidor.getLlavesCifrado().get(Repetidor.KEY_REPETIDOR_PRIVADA);
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoCliente);
        byte[] idMsjDescifrado = Asimetrico.descifrar( keyRepetidorPrivada, bytes);
        return idMsjDescifrado;
    }

    /* ****************************************************************
    * 			Cifrado Simétrico
    *****************************************************************/

    /**
     * Se encarga del cifrado simétrico de la identificación del mensaje del cliente.
     * @param idMsjDescifradoCliente Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoSimetricoMensaje2Servidor(byte[] idMsjDescifradoCliente){
        SecretKey repetidor2Servidor = (SecretKey) repetidor.getLlavesCifrado().get(Repetidor.KEY_REPETIDOR2SERVIDOR);
        String str = new String( idMsjDescifradoCliente ) ; 
        byte[] msjCifrado = Simetrico.cifrar( repetidor2Servidor, str);
        return msjCifrado ;
    }

    /**
     * Se encarga del cifrado simétrico del mensaje del servidor.
     * @param idMsjDescifradoServidor Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoSimetricoMensaje2Cliente(int idCliente, byte[] idMsjDescifradoServidor){
        SecretKey repetidor2Cliente = (SecretKey) repetidor.getLlavesCifrado().get(Repetidor.BEGIN_KEYS_CLIENTE2REPETIDOR+idCliente);
        String str = new String( idMsjDescifradoServidor ) ; 
        byte[] msjCifrado = Simetrico.cifrar( repetidor2Cliente, str);
        return msjCifrado ;
    }

    /* ****************************************************************
    * 			Cifrado Asimétrico
    *****************************************************************/    

    /**
     * Se encarga del cifrado asimétrico de la identificación del mensaje del cliente.
     * @param idMsjDescifradoCliente Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoAsimetricoMensaje2Servidor(byte[] idMsjDescifradoCliente){
        PublicKey servidorPublica = (PublicKey) repetidor.getLlavesCifrado().get(Repetidor.KEY_SERVIDOR_PUBLICA);
        String str = new String( idMsjDescifradoCliente );
        byte [] msjCifrado = Asimetrico.cifrar( servidorPublica, str);
        return  msjCifrado;
    }

    /**
     * Se encarga del cifrado asimétrico del mensaje del servidor.
     * @param idMsjDescifradpServidor Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoAsimetricoMensaje2Cliente(int idCliente, byte[] idMsjDescifradoServidor){
        PublicKey clientePublica = (PublicKey) repetidor.getLlavesCifrado().get(Repetidor.BEGIN_KEYS_CLIENTES_PUBLICAS+idCliente);
        String str = new String( idMsjDescifradoServidor );
        byte [] msjCifrado = Asimetrico.cifrar( clientePublica, str);
        return  msjCifrado;
    }

    /* ****************************************************************
    * 			Run
    *****************************************************************/     
    
    @Override
    public void run(){
        String idMsjCifradoC2R = null; 
        byte[] idMsjCifradoR2S  = null;
        byte[] idMsjCifradoR2C = null;
        byte[] idMsjDescifradoC = null, idMsjDescifradoS = null; 
        try{

            int cifrado = repetidor.getCifrado();

            String clienteMsg = inputCliente.readLine();
            int idCliente = Integer.parseInt( clienteMsg.split("_")[1] );

            outputCliente.println("Ok");
            outputCliente.flush();
            
            idMsjCifradoC2R = inputCliente.readLine();
        
            if( cifrado == Repetidor.CIFRADO_SIMETRICO){
                idMsjDescifradoC = descifradoSimetricoMensajeCliente(idCliente, idMsjCifradoC2R);
                
                idMsjCifradoR2S = cifradoSimetricoMensaje2Servidor( idMsjDescifradoC );
            } 
            else{
                idMsjDescifradoC = descifradoAsimetricoMensaje(idMsjCifradoC2R);
                System.out.println( "--------" + new String( idMsjDescifradoC ) + "--------" );
                idMsjCifradoR2S = cifradoAsimetricoMensaje2Servidor(idMsjDescifradoC);
            } 

            init2();
            
            outputServidorDelegado.println( TransmisionBytes.byte2Str(idMsjCifradoR2S) );
            outputServidorDelegado.flush();

            String mensaje = inputServidorDelegado.readLine();

            if( cifrado == Repetidor.CIFRADO_SIMETRICO){
                idMsjDescifradoS = descifradoSimetricoMensajeServidor(mensaje);
                idMsjCifradoR2C = cifradoSimetricoMensaje2Cliente( idCliente, idMsjDescifradoS );
            } 
            else{
                idMsjDescifradoS = descifradoAsimetricoMensaje(mensaje);
                idMsjCifradoR2C = cifradoAsimetricoMensaje2Cliente(idCliente, idMsjDescifradoS);
            } 

            outputCliente.println( TransmisionBytes.byte2Str( idMsjCifradoR2C ) );
            outputCliente.flush();

            cliente.close();
            System.out.println("Cliente desconectado.");
        }
        catch(IOException e){
            e.printStackTrace();
        } 
    }
 }