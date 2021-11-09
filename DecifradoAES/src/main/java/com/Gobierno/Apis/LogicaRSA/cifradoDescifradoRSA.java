package com.Gobierno.Apis.LogicaRSA;

import com.gobierno.apis.seguridad.exceptions.MessageException;
import javax.crypto.*;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpStatus;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
public class cifradoDescifradoRSA {
	
	 private static final String llavePrivada="MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAJoFwLq24NlY9YH6OEvMvo7P+ejERsW4xvW3Gb6DjMJFKc0XP9gzmiVhXrjHVkxLvdL1eoNQ+yfLLER442ZqC73Awt6iF+8pMyaqkZ54w1dUtftuT4BqEi0NH/JSrV07r83U11naLmvI9CF4YTgrjV6+5It/MvqkUIzfVTCxlK8JAgMBAAECgYAh8rSpMtfacCYk0O8JngY+Wg7eRCzJNdH8pK/y8vHae/4bq00yLSWDqbOEDMOzq1oanmqzeOzyt3B5Yx/UGfmeMIWCzRX9sbJNDi901g5ihmHEfSQf/rBRXjoKmdOeuGQ/9Ukp7w0nM7iFNLJbXuNYLYGdqZJeS0mz5Dzva6s0tQJBANdGYhw2JGONm8H4KlpJk4Xdm1l/oHbpz4hfe03SqVHSwaeIs7uk4NEEDOE82V2N+FC14NrkdlxJj8YAFagZWRMCQQC3KPR+Nj5BuKJPrnjS+W08/BaWkIPL80ASb2NU65CXs/X6owDszoOQEl/jliWcM+kQmA8EpSVrYi9XzpS53JbzAkBMCvKxIHbuK6FvfSgIyKCx0rwDe0/FcYX7mC7IKLfizV3WvjUu/WjkrFeYYJQvteyXJggNilI8+0csG++Kd5m9AkAtX3TpyzAzAbUbviHqSaXZBK3n0JcFsBXAO13FDLH+ErOtyjGReDs5NoQQkgJxJp7m4HRf9zVE28bUnrVTMaUnAkBlIIUx185f1bHE//BR5Iemtkx7GMX6G2l3yR7OKOXLY4XFv3jgnI+IZNRwRN7eR+SUaW7tJv/YDwLXM47Wvn9n";
	 private static final String llavePublica ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCaBcC6tuDZWPWB+jhLzL6Oz/noxEbFuMb1txm+g4zCRSnNFz/YM5olYV64x1ZMS73S9XqDUPsnyyxEeONmagu9wMLeohfvKTMmqpGeeMNXVLX7bk+AahItDR/yUq1dO6/N1NdZ2i5ryPQheGE4K41evuSLfzL6pFCM31UwsZSvCQIDAQAB";
	 private static final String ALGORITHM__RSA="RSA/ECB/PKCS1Padding";
	 private static final String ENCODING_UTF8 = "UTF8";
	 
	public String encrypRSA(String texto) { 
		String textoCifrado=null;
		try {
			Cipher rsaCipher = Cipher.getInstance(ALGORITHM__RSA);
			rsaCipher.init(Cipher.ENCRYPT_MODE, obtenerPublicKey(llavePublica));
			byte[] mensajeCifrado = rsaCipher.doFinal(texto.getBytes(ENCODING_UTF8));
			textoCifrado=Base64.encodeBase64String(mensajeCifrado);
			System.out.println(Base64.encodeBase64String(mensajeCifrado));
		}catch(Exception e) {
			System.out.print(e.getMessage());
		}
		
		return textoCifrado;
	}
	
	
	public String dencrypRSA(String textoCifrado) {
		String textoDescifrado=null;
		try {
			 Cipher rsaCipher = Cipher.getInstance(ALGORITHM__RSA);
			 rsaCipher.init(Cipher.DECRYPT_MODE, obtenerPrivateKey(llavePrivada));
			 System.out.println(obtenerPrivateKey(llavePrivada));
			 textoDescifrado = new String(rsaCipher.doFinal(Base64.decodeBase64(textoCifrado)), ENCODING_UTF8);
		}catch(Exception e) {
			System.out.print(e.getMessage());
		}
		
		return textoDescifrado;
	}

	
	public PublicKey obtenerPublicKey(String PUBLICKEYPEM)throws MessageException{
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
		try {
			byte[] decode = Base64.decodeBase64(PUBLICKEYPEM);
			X509EncodedKeySpec spec = new X509EncodedKeySpec(decode);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePublic(spec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException var4) {
			throw new MessageException(1000, HttpStatus.INTERNAL_SERVER_ERROR, var4.getMessage());
		}
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
	}
	
	public PrivateKey obtenerPrivateKey(String PRIVATEKEYPEM)throws MessageException{
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
		try {
			byte[] decode = Base64.decodeBase64(PRIVATEKEYPEM);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decode);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException var4) {
			throw new MessageException(1000, HttpStatus.INTERNAL_SERVER_ERROR, var4.getMessage());
		}
		/*******************NO MODIFICAR LOS DATOS DE ESTA FUNCIÓN PARA LA CORRECTA IMPLEMENTACIÓN **********************/
	}
}
 
