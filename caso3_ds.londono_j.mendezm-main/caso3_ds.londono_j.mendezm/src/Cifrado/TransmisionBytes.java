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

    public class TransmisionBytes {

   /* ****************************************************************
    * 			Métodos
    *****************************************************************/

    /**
     * Transforma un arreglo de bytes a cadenas de caracteres.
     * @param b Arreglo de bytes a transformar
     * @return Cadena de caracteres correspondiente al byte. 
     */
    public static String byte2Str( byte[] b ){
        String ret = "";
        for(int i=0; i<b.length; i++){
            String g = Integer.toHexString( ((char) b[i]) &0x00ff);
            ret += (g.length()==1?"0":"")+g;
        }
        return ret; 
    } 

    /**
     * Transforma cadenas de caracteres a bytes.
     * @param ss Cadena de caracteres a transformar
     * @return Arreglo de bytes correspondient a la cadena de caracteres. 
     */
    public static byte[] srt2Byte( String ss){
        byte[] ret = new byte[ss.length()/2];
        for(int i=0; i<ret.length; i++){
            ret[i] += (byte) Integer.parseInt( ss.substring(i*2, (i+1)*2), 16 );
        }
        return ret; 
        } 
    }
