import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

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
 * Clase que representa el servidor delegado de la aplicación
 */
 public class ServidorDelegado extends Thread{
 
    /* ****************************************************************
    * 			Atributos
    *****************************************************************/

     /**
     * Representa una instancia de la clase Servidor
     */
    private Servidor servidor; 

    /**
     * Socket del repetidor delegado a ser atentido.
     */
    private Socket repetidorDelegado; 

    /**
     * Medio de comunicación: Repetipor delegado -> Servidor delegado .
     */
    private BufferedReader input; 

    /**
     * Medio de comunicación: Servidor delegado -> Repetidor delegado.  
     */
    private PrintWriter output; 

   /* ****************************************************************
    * 			Constructor
    *****************************************************************/   
    
    public ServidorDelegado(Servidor servidor, Socket repetidorDelegado){
        this.servidor = servidor;
        this.repetidorDelegado = repetidorDelegado; 
        System.out.println("Repetidor delegado conectado.");
        init();
    }

    /**
     * Inicializa el Servidor delegado.
     */
    public void init(){
        try{
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
     * @param idMsjDescifradoRepetidor Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoSimetricoMensaje(String resMensaje){
        SecretKey repetidor2Servidor = (SecretKey) servidor.getLlavesCifrado().get(Repetidor.KEY_REPETIDOR2SERVIDOR);
        byte[] msjCifrado = Simetrico.cifrar( repetidor2Servidor, resMensaje);
        return msjCifrado ;
    }

    /**
     * Se encarga del cifrado asimétrico de la identificación del mensaje del cliente.
     * @param idMsjDescifradoRepetidor Identificación del mensaje a cifrar.
     * @return Arreglo de bytes de la identificación del mensaje cifrado.
     */
    public byte[] cifradoAsimetricoMensaje(String resMensaje){
        PublicKey repetidorPublica = (PublicKey) servidor.getLlavesCifrado().get(Servidor.KEY_REPETIDOR_PUBLICA);
        byte [] msjCifrado = Asimetrico.cifrar( repetidorPublica, resMensaje);
        return  msjCifrado;
    }

    /* ****************************************************************
    * 			Descifrado
    *****************************************************************/

    /**
     * Se encarga del descifrado simétrico de la identificación del mensaje del cliente.
     * @param idCliente Identificación del cliente.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoSimetricoMensaje(String idMsjCifradoR2S){
        SecretKey repetidor2Servidor = (SecretKey) servidor.getLlavesCifrado().get( Servidor.KEY_REPETIDOR2SERVIDOR );
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoR2S);
        byte[] idMsjDescifrado = Simetrico.descifrar( repetidor2Servidor, bytes);
        return idMsjDescifrado; 
    }

    /**
     * Se encarga del descifrado asimétrico de la identificación del mensaje del cliente.
     * @param idCliente Identificación del cliente.
     * @return Arreglo de bytes de la identificación del mensaje descifrado.
     */
    public byte[] descifradoAsimetricoMensaje(String idMsjCifradoR2S){
        PrivateKey repetidor2Servidor = (PrivateKey) servidor.getLlavesCifrado().get( Servidor.KEY_SERVIDOR_PRIVADA );
        byte[] bytes = TransmisionBytes.srt2Byte(idMsjCifradoR2S);
        byte[] idMsjDescifrado = Asimetrico.descifrar( repetidor2Servidor, bytes);
        return idMsjDescifrado; 
    }

    /* ****************************************************************
    * 			Run
    *****************************************************************/ 

    @Override
    public void run(){
        byte[] idMsjDescifradoR = null;
        byte[] idMsjCifradoS2R = null;

        try{
            int cifrado = servidor.getCifrado();
            String idMsjCifradoR2S = input.readLine();

            if( cifrado == Servidor.CIFRADO_SIMETRICO){
                idMsjDescifradoR = descifradoSimetricoMensaje(idMsjCifradoR2S);
                String idMensaje = new String( idMsjDescifradoR );
                String resMensaje = servidor.getMensajes().get( Integer.parseInt(idMensaje) );

                idMsjCifradoS2R = cifradoSimetricoMensaje( resMensaje );
            } 
            else{
                idMsjDescifradoR = descifradoAsimetricoMensaje(idMsjCifradoR2S);

                String idMensaje = new String( idMsjDescifradoR );
                String resMensaje = servidor.getMensajes().get( Integer.parseInt(idMensaje) );

                idMsjCifradoS2R = cifradoAsimetricoMensaje( resMensaje );
            } 

            output.println( TransmisionBytes.byte2Str(idMsjCifradoS2R) );
            output.flush();

            repetidorDelegado.close();
            System.out.println("Repetidor delegado desconectado.");
        }
        catch(IOException e){
            e.printStackTrace();
        } 
    }
 }