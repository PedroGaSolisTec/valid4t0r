package com.Gobierno.Apis.LogicaAES;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.HttpStatus;
import com.gobierno.apis.seguridad.exceptions.MessageException;

public class cifrarDescifrarAES {

	 private static final String ENCODING_UTF8 = "UTF-8";
	 private static final String AES_KEY = "AES";
	 private static final String ALGORITHM_AES = "AES/CBC/PKCS5Padding";
	 private static final String ALGORITHM_HMAC = "HmacSHA256";
	 private static final int IV_SIZE = 16;

	 
		public String encriptar(String accesoSimetrico, String codigoAutentificacionHash, String valor) throws MessageException{
			
				String respuesta=null;
				try {
					respuesta = encryptAes(accesoSimetrico,codigoAutentificacionHash,valor);
					System.out.println("################################################################");
					System.out.println(accesoSimetrico);
					System.out.println(codigoAutentificacionHash);
					System.out.println("################################################################");
				} catch (MessageException e) {
					System.out.print(e.getMessage());
					throw new MessageException(1008, HttpStatus.BAD_REQUEST,e.getMessage());
				}

			return respuesta;
		}
		
		public String desEncriptar(String accesoSimetrico, String codigoAutentificacionHash, String valorCifrado) throws MessageException {
			
			String respuesta=null;
			try {
				respuesta = decryptAes(accesoSimetrico,codigoAutentificacionHash,valorCifrado);
				System.out.println("################################################################");
				System.out.println(accesoSimetrico);
				System.out.println(codigoAutentificacionHash);
				System.out.println("################################################################");
			}catch (Exception e) {
				System.out.print(e.getMessage());
				throw new MessageException(1008, HttpStatus.BAD_REQUEST,e.getMessage());
			}
			return respuesta;
		}
	 
	 
	 
	    public String encryptAes(String aesKeyBase64, String hmacKeyBase64,String valorCampo) throws MessageException {
	        try {
	            SecretKeySpec aesKey = new SecretKeySpec(Base64.getDecoder().decode(aesKeyBase64.getBytes(ENCODING_UTF8)), AES_KEY);
	            SecretKeySpec hmacKey = new SecretKeySpec(Base64.getDecoder().decode(hmacKeyBase64.getBytes(ENCODING_UTF8)), ALGORITHM_HMAC);
	            
	            byte[] iv = generarInitializationVector();
	            
	            Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
	            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
	            
	            byte[] plainText= valorCampo.getBytes(ENCODING_UTF8);
	            
	            byte[] cipherText = cipher.doFinal(plainText);
	            byte[] iv_cipherText = concatenateBytes(iv, cipherText);
	            byte[] hmac = generarHMAC(hmacKey, iv_cipherText);
	            byte[] iv_cipherText_hmac = concatenateBytes(iv_cipherText, hmac);
	    
	            byte[] iv_cipherText_hmac_base64 = Base64.getEncoder().encode(iv_cipherText_hmac);
	            return new String(iv_cipherText_hmac_base64, ENCODING_UTF8);             
	        
	        } catch (Exception e) {
	        	 throw new MessageException(1008, HttpStatus.BAD_REQUEST,e.getMessage());
	        }
	    }
	    
	    public String decryptAes(String aesKeyBase64, String hmacKeyBase64, String valorCifrado) throws MessageException {
	        try {
	            SecretKeySpec aesKey = new SecretKeySpec(Base64.getDecoder().decode(aesKeyBase64.getBytes(ENCODING_UTF8)), AES_KEY);
	            SecretKeySpec hmacKey = new SecretKeySpec(Base64.getDecoder().decode(hmacKeyBase64.getBytes(ENCODING_UTF8)), ALGORITHM_HMAC);
	        
	            int macLength = obtenerHMACLength(hmacKey);
	            
	            byte[] iv_cipherText_hmac = Base64.getDecoder().decode(valorCifrado.getBytes(ENCODING_UTF8));
	            int cipherTextLength = iv_cipherText_hmac.length - macLength;
	            
	            byte[] iv = Arrays.copyOf(iv_cipherText_hmac, IV_SIZE);
	            byte[] cipherText = Arrays.copyOfRange(iv_cipherText_hmac, IV_SIZE, cipherTextLength);
	            byte[] iv_cipherText = concatenateBytes(iv, cipherText);
	            byte[] receivedHMAC = Arrays.copyOfRange(iv_cipherText_hmac, cipherTextLength, iv_cipherText_hmac.length);
	            byte[] calculatedHMAC = generarHMAC(hmacKey, iv_cipherText);
	            
	            if(Arrays.equals(receivedHMAC, calculatedHMAC)) {
	                Cipher cipher = Cipher.getInstance(ALGORITHM_AES);
	                cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
	                byte[] plainText = cipher.doFinal(cipherText);
	                return new String(plainText,ENCODING_UTF8);
	            } else {
	                return valorCifrado;
	            }
	            
	        } catch (Exception e) {
	        	throw new MessageException(1008, HttpStatus.BAD_REQUEST,e.getMessage());
	        } 
	    }
	    
	    
	    
	    /***********FUNCIONES COMPLEMENTARIAS****************/

	    private byte[] generarInitializationVector() {
	        byte[] iv = new byte[IV_SIZE];
	        SecureRandom secureRandom = new SecureRandom();
	        secureRandom.nextBytes(iv);	
	        return iv;
	    }

	    private byte[] concatenateBytes(byte[]first, byte[] second) {
	        byte [] concatBytes = new byte[first.length + second.length];
	        System.arraycopy(first, 0, concatBytes, 0, first.length);
	        System.arraycopy(second, 0, concatBytes, first.length, second.length);
	        return concatBytes;
	    }

	    private int obtenerHMACLength(SecretKey key) throws NoSuchAlgorithmException, InvalidKeyException {
	        Mac hmac = Mac.getInstance(ALGORITHM_HMAC);
	        hmac.init(key);
	        return hmac.getMacLength();
	   }
	 

	    private byte[] generarHMAC(SecretKey key, byte[] hmacInput) throws NoSuchAlgorithmException, InvalidKeyException {
	        Mac hmac = Mac.getInstance(ALGORITHM_HMAC);
	        hmac.init(key);
	        return hmac.doFinal(hmacInput);
	    }
	
	    /**********FIN DE FUNCIONES COMPLEMENTARIAS*******************/
}
