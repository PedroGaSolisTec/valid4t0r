package com.Gobierno.Apis.RespuestaAES;

public class Subrespuesta {
	
	
	private String idAcceso;
	private String accesoPublico;
	private String accesoPrivado;
	private String accesoSimetrico;
	private String codigoAutentificacionHash;
		
	public void setIdAcceso(String idAcceso) {
		this.idAcceso = idAcceso;
	}

	public void setAccesoPublico(String accesoPublico) {
		this.accesoPublico = accesoPublico;
	}

	public void setAccesoPrivado(String accesoPrivado) {
		this.accesoPrivado = accesoPrivado;
	}

	public void setAccesoSimetrico(String accesoSimetrico) {
		this.accesoSimetrico = accesoSimetrico;
	}

	public String getIdAcceso() {
		return idAcceso;
	}

	public String getAccesoPublico() {
		return accesoPublico;
	}

	public String getAccesoPrivado() {
		return accesoPrivado;
	}

	public String getAccesoSimetrico() {
		return accesoSimetrico;
	}

	public String getCodigoAutentificacionHash() {
		return codigoAutentificacionHash;
	}

	public void setCodigoAutentificacionHash(String codigoAutentificacionHash) {
		this.codigoAutentificacionHash = codigoAutentificacionHash;
	}
	

}
