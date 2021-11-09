package com.Gobierno.Apis.LogicaAES;

import com.Gobierno.Apis.RespuestaAES.Respuesta;
import com.Gobierno.Apis.RespuestaAES.Subrespuesta;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletResponse;

public class generadorLlaves {

	private static final String AES_KEY = "AES";
	private static final String ALGORITHM_HMAC = "HmacSHA256";
	private static final int KEY_SIZE = 256;

	private SecretKey secretKey = accesoSimetrico();
	private String accesoSimetricoGen = Base64.getEncoder().encodeToString(secretKey.getEncoded());
	private String codigoAutentificacionHashGen = Base64.getEncoder().encodeToString(generarHMAC(secretKey,"gda-apis".getBytes()));


	public Respuesta Obtener(HttpServletResponse response){
		
		Respuesta respuesta= new Respuesta();
		Subrespuesta subrespuesta= new Subrespuesta();
		
		/*Inicio de Mensaje*/
		
		respuesta.setCodigo("200.Mensaje-de-Prueba.100200");
		respuesta.setMensaje("Operación exitosa");
		respuesta.setFolio("Folio-de-Prueba");
		subrespuesta.setIdAcceso("idAcceso-de-Prueba");
		subrespuesta.setAccesoPublico("accesoPublico-de-prueba");
		subrespuesta.setAccesoPrivado("accesoPrivado-de-Prueba");
		subrespuesta.setAccesoSimetrico(accesoSimetricoGen);
		subrespuesta.setCodigoAutentificacionHash(codigoAutentificacionHashGen);
		respuesta.setResultado(subrespuesta); 
		
		/*Fin de Mensaje*/
		
		return respuesta;
	}


		public	SecretKey accesoSimetrico(){

	        KeyGenerator keyGenerator = null;

	            try {
					keyGenerator = KeyGenerator.getInstance(AES_KEY);
				} catch (NoSuchAlgorithmException e) {
					System.out.println("Ocurrio un error");
				}
	            keyGenerator.init(KEY_SIZE);
	            SecretKey clave = keyGenerator.generateKey();	        
	            return clave;
	    }



	    public byte[] generarHMAC(SecretKey key, byte[] hmacInput) {

	    	Mac hmac = null;

	            try {
					hmac = Mac.getInstance(ALGORITHM_HMAC);
					hmac.init(key);
				} catch (Exception e) {
					System.out.println(e.getMessage());
				}
	     return hmac.doFinal(hmacInput);
	    }

}

