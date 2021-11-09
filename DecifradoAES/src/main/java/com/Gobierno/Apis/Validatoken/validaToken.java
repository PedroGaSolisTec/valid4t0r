package com.Gobierno.Apis.Validatoken;

/*ESTAS LIBRERIAS SON PROPIAS DE GOBIERNO DE APIs Y NO DEBEN SER SUSTITUIDAS*/
import com.gobierno.apis.seguridad.exceptions.MessageException;
import com.gobierno.apis.seguridad.to.ResponseErrorTO;
import com.gobierno.apis.seguridad.util.Utileria;
/*FIN*/


import org.apache.commons.codec.binary.Base64; //EL USO DE ESTA LIBRERIA ES INDISPENSABLE PARA EL CORRECTO 
/*FUNCIONAMIENTO DE LA IMPLEMENTACIÓN (NOTA: no debe ser sustituida por otra)*/

import io.jsonwebtoken.*;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


@Component
public class validaToken {
	
	private static final Logger LOG = LoggerFactory.getLogger(validaToken.class);
	
	private static String PUBLICKEYPEM_2048Bytes ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyGpkUJ6m2WLm4WMHtpszcd3TxjLOJJDRVnv4GA7lROcz3xCe94IjCEzofVkafgqMYwCKKtjFHJZzGvV6Pe39jacBp4a5YZRv5/3ZgqnEo5sllNTbOblLCnSiiXzYx+slKYgcPr4zGFSROQekSdEjDCRmfiuyKKroutsJCNYXJiT8RrWl/jmyyT4Fn6kSnT6QP4fvQ7jhI55T+B/c5hTeYphpwe5dX1mYJr2swjy0bSZYQwSGXUk/W7jsTpFQjM8eT7W+hQJHZKVOFTntnEC7UdRUNxGN6Q2kre7I7lOVREXj9/bH+sboJk26Vu7G1pv3QHL7C/p9/SBjO8uWX+TbjQIDAQAB"; //Llave a 2048
	//private static String PUBLICKEYPEM_1024Bytes = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfN9o3x8jq3awrDapaxzSNbAJWe3RXFmwZ0oVCTQQnvcA05h3XMUa+FNeYlo7UpYOEJTBFf7tqM4WEIz2C9dNyOUl3cwNUkVb9y35thyvPAd1zD6FaO+lgL/mpQVF03/pSR8taSj3sdDVXVdlt/6VMRagDqcNZiSc07p7UKVhO7wIDAQAB"; //Llave a 1024
	
	private static String USUARIO ="apigee"; /*INICIALIZAMOS LA VARIBALE USUARIO CON EL VALOR "apigee" PORQUE 
	EL TOKEN VIENE FIRMADO DE ESA MANERA DE LOS CONTRARIO NO SERIA UN TOKEN VALIDO*/
	
	
	public static void validarToken(HttpServletRequest request, HttpServletResponse response) {
		
		/*******************ESTA FUNCION SE DEBE MODIFICAR PARA LA IMPLEMENTACIÓN  EN SU BACK-END**********************/
		
		request.setAttribute("startTime", System.currentTimeMillis());
		boolean BANDERA = true;
		 
		try {
			
			validaJWT(request.getHeader("token"), PUBLICKEYPEM_2048Bytes);
			
		}catch (MessageException Err0) {
			/*SI EL ERROR SE GENERA EN ESTE PUNTO SIGNIFICA QUE NO SE RECIBIO UN TOKEN*/
			crearResponseIncidencia(response, 401, Err0, "¡No estás autorizado!. Favor de validar");
			BANDERA = false;			
			
		}catch (SignatureException Err0) {
			/*SI EL ERROR SE GENERA EN ESTE PUNTO SIGNIFICA QUE UTILIZAS UN TOKEN GENERADO CON LLAVE PRIVADA A 1024 Y SE ESPERABA
			 * UNO A 2048 O VICERVERSA */
			crearResponseIncidencia(response, 401, Err0, "Token invalido");
			BANDERA = false;
			
		}catch (MalformedJwtException Err0) {
			/*SI EL ERROR SE GENERA EN ESTE PUNTO SIGNIFICA QUE EL TOKEN FUE MODIFICADO*/
			crearResponseIncidencia(response, 401, Err0, "¡Formato no valido!");
			BANDERA = false;
			
		}catch (ExpiredJwtException Err0) {
			/*SI EL ERROR SE GENERA EN ESTE PUNTO SIGNIFICA QUE EL TOKEN YA EXPIRÓ */
			crearResponseIncidencia(response, 401, Err0, "¡El token a expirado!");
			BANDERA = false;
			
		}catch (Exception Err0) {
			/*NO SE PUDO PROCESAR LA SOLICITUD*/
			crearResponseIncidencia(response, 401, Err0, "¡Solicitud no valida!");
			BANDERA = false;
		}
		
		if(BANDERA) {
			/*SI BANDERA ES TRUE SIGNIFICA QUE EL TOKEN ES VALIDO Y POR ENDE PRODIA HACERSE USO DE LAS APIs*/
			crearResponseIncidencia(response,200, null, "¡Token valido!");
		}
		
		LOG.info("Bandera es: " + BANDERA);
	}
	
	
	
	public static void validaJWT(String token, String PUBLICKEYPEM) throws MessageException{
		
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
		
		SimpleDateFormat formatoFecha = new SimpleDateFormat("dd/mm/yyyy hh:mm:ss aa");
		
		if(token != null && !token.isEmpty()) {
			
			PublicKey publicKey = obtenerPublicKey(PUBLICKEYPEM);
			System.out.println(publicKey);
			Claims claims = (Claims)Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token).getBody();
			LOG.info("Informacion de token: {}", claims.toString());
			
			if (claims.getSubject() != null && (new Utileria()).desencriptarTextoRSA(claims.getSubject()).equals(USUARIO)) {
				Date tiempoExpiracionJWT = claims.getExpiration();
				String fecha = tiempoExpiracionJWT != null ? formatoFecha.format(tiempoExpiracionJWT) : "Sin expiracion" ; 
				LOG.info("El token expira el: {}", fecha);
			}else {
				LOG.info("¡Usuario no valido!");
				throw new MessageException(1008, HttpStatus.BAD_REQUEST, "Usuario invalido");
			}
		}else {
			LOG.info("¡El toke es requerido!");
			throw new MessageException(1008, HttpStatus.BAD_REQUEST, "Usuario invalido");
		}
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
	}
	
	private static PublicKey obtenerPublicKey(String PUBLICKEYPEM)  throws MessageException{
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
		try {
			byte[] decode = Base64.decodeBase64(PUBLICKEYPEM);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decode);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException var4) {
			LOG.error("", var4);
			throw new MessageException(1000, HttpStatus.INTERNAL_SERVER_ERROR, var4.getMessage());
		}
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
	}


	private static void crearResponseIncidencia(HttpServletResponse response, int status, Exception ex, String mensaje) {
		
		/*****EL USO DE ESTA FUNCIÓN EN LA IMPLEMENTACIÓN DE TÚ BACK-END ES OPCIONAL ******/
		/***** YA QUE SOLO SE UTILIZA PARA MOSTRAR LA RESPUESTA*****/
		
		ResponseErrorTO responseErrorTO = new ResponseErrorTO(status+".Mensaje-de-prueba."+status, mensaje, UUID.randomUUID().toString(), 
				"https://bazdeveloper.bancoazteca.com.mx/info#"+status+".Mensaje-de-prueba."+status);
		
		responseErrorTO.setDetalle("Mensaje de control");
		response.setContentType("application/json");
		response.setStatus(status);
			
			if(status!=200) {
	        	LOG.info(ex.getMessage());
	        }

		try {
			response.getWriter().write(Utileria.objetoAJson(responseErrorTO));			
		}catch (MessageException | IOException var8) {
			IOException e = (IOException) var8;
			try {
				response.getWriter().write("\"Mensaje\":\"" + e + "\"");
			} catch (IOException var7) {
			LOG.error("Incidencia al parsear el Objeto a JSon..." + var7);
			}
		}
		
	}
}
