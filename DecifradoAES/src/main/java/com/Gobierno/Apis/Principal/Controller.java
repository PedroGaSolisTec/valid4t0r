package com.Gobierno.Apis.Principal;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import com.Gobierno.Apis.LogicaAES.cifrarDescifrarAES;
import com.Gobierno.Apis.LogicaAES.generadorLlaves;
import com.Gobierno.Apis.LogicaRSA.cifradoDescifradoRSA;
import com.Gobierno.Apis.RespuestaAES.Respuesta;
import com.Gobierno.Apis.Validatoken.validaToken;
import com.gobierno.apis.seguridad.exceptions.MessageException;
import com.gobierno.apis.seguridad.util.Utileria;


/*localhost:8080/Endpoint-a-consumir*/

@RestController
public class Controller extends HttpServlet {
    private static final long serialVersionUID = 1L;
    
    @GetMapping("/token")/*Para hacer uso solo hay que enviar por "Header" un [[token]] para validar*/
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	validaToken.validarToken(request, response);
    }

    @GetMapping("/llaves")/*No hay que enviar ningun Header respondera con accessoSimetrico y codigoAutenticacionHash*/
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	generadorLlaves key=new generadorLlaves();
    	Respuesta respuesta= key.Obtener(response);
		try {
	    	response.setContentType("application/json");
	        response.setStatus(200);
			response.getWriter().write(Utileria.objetoAJson(respuesta));
		} catch (IOException | MessageException e) {
			System.out.print("Ocurrio un error"+ e.getMessage());
	        response.setStatus(500);
			response.getWriter().write("No se puedo procesar la solicitud");
		}
    }

    
    
    @PostMapping("/encriptarRSA")/**/
    protected void encriptarRSA(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	cifradoDescifradoRSA encriptarRSA=new cifradoDescifradoRSA();
    	
		try {
			String respuesta=encriptarRSA.encrypRSA(request.getHeader("texto"));
	    	response.setContentType("application/text");
	        response.setStatus(200);
			response.getWriter().write(respuesta);
		} catch (Exception e) {
	        response.setStatus(500);
	        response.getWriter().write("No se pudo procesar la solicitud\n\n"+e.getMessage());
		}
    }
    
    
    @PostMapping("/desEncriptarRSA")/**/
    protected void desEncriptarRSA(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	cifradoDescifradoRSA desEncriptarRSA=new cifradoDescifradoRSA();
    	
		try {
			String respuesta=desEncriptarRSA.dencrypRSA(request.getHeader("textoCifrado"));
	    	response.setContentType("application/text");
	        response.setStatus(200);
			response.getWriter().write(respuesta);
		} catch (Exception e) {
	        response.setStatus(500);
			response.getWriter().write("No se pudo procesar la solicitud\n\n"+e.getMessage());
		}
    }
    
    
    @PostMapping("/encriptarAES")/* Para hacer uso hay que enviar por Header [[accesoSimetrico]], [[codigoAutentificacionHash]] (Obtenidos de "/llaves") y [[valor]] a encriptar*/
    protected void encriptarAES(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	cifrarDescifrarAES Encriptar=new cifrarDescifrarAES();
    	
		try {
			String respuesta=Encriptar.encriptar(request.getHeader("accesoSimetrico"),request.getHeader("codigoAutentificacionHash"),request.getHeader("valor"));
	    	response.setContentType("application/text");
	        response.setStatus(200);
			response.getWriter().write(respuesta);
		} catch (IOException | MessageException e) {
	        response.setStatus(500);
			response.getWriter().write("No se pudo procesar la solicitud");
		}
    }
    
    
    @PostMapping("/desEncriptarAES")/*Para hacer uso hay que enviar po Header [[accesoSimetrico]], [[codigoAutentificacionHash]] (Obtenidos de "/llaves") y [[valorCifrado]] a desencriptar*/
    protected void desEncriptarAES(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    	cifrarDescifrarAES Desencriptar=new cifrarDescifrarAES();
		try {
			String respuesta=Desencriptar.desEncriptar(request.getHeader("accesoSimetrico").trim(),request.getHeader("codigoAutentificacionHash").trim(),request.getHeader("valorCifrado"));
	    	response.setContentType("application/text");
	        response.setStatus(200);
			response.getWriter().write(respuesta);
		} catch (IOException | MessageException e) {
	        response.setStatus(500);
			response.getWriter().write("No se pudo procesar la solicitud");
		}
    }
    
    
}