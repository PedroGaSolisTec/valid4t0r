package com.Gobierno.Apis.RespuestaAES;



public class Respuesta {
	
	private String codigo;
	private String mensaje;
	private String folio;
	private Subrespuesta resultado;

	
	public String getCodigo() {
		return codigo;
	}

	public String getMensaje() {
		return mensaje;
	}

	public String getFolio() {
		return folio;
	}

	public Subrespuesta getResultado() {
		return resultado;
	}

	public void setCodigo(String codigo) {
		this.codigo = codigo;
	}
	
	public void setMensaje(String mensaje) {
		this.mensaje = mensaje;
	}

	public void setFolio(String folio) {
		this.folio = folio;
	}

	public void setResultado(Subrespuesta resultado) {
		this.resultado = resultado;
	}

}
