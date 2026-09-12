"""Descriptor descubierto sin importar ni arrancar el servidor de red."""

from ipaddress import ip_address
from pathlib import Path

from pydantic import BaseModel, Field, field_validator, model_validator

from atalaya.core.module import Category
from atalaya.core.service import ServiceContext, ServiceModule


class HoneypotInputs(BaseModel):
    host: str = Field("127.0.0.1", description="IP local de escucha SSH; 0.0.0.0 para exponerlo.")
    port: int = Field(2222, ge=1024, le=65535, description="Puerto SSH sin privilegios.")
    dashboard_host: str = Field("127.0.0.1", description="IP de loopback para el panel privado.")
    dashboard_port: int = Field(8080, ge=1024, le=65535, description="Puerto del panel.")
    data_dir: Path = Field(
        ".atalaya-honeypot", validate_default=True, description="Directorio privado de estado."
    )
    geoip_db: Path | None = Field(None, description="Base City .mmdb local, opcional para el mapa.")
    max_connections: int = Field(64, ge=1, le=256, description="Conexiones SSH simultáneas.")
    max_per_ip: int = Field(3, ge=1, le=16, description="Conexiones simultáneas por IP.")
    connection_rate: int = Field(20, ge=1, le=100, description="Admisiones globales por segundo.")
    ip_rate: int = Field(5, ge=1, le=20, description="Admisiones por IP por segundo.")
    login_timeout: float = Field(15, ge=0.1, le=60, description="Vida máxima de una conexión.")
    max_attempts: int = Field(6, ge=1, le=20, description="Contraseñas por conexión.")
    auth_delay: float = Field(
        0.25, ge=0.05, le=2, description="Pausa entre rechazos de contraseña."
    )
    retention_hours: int = Field(24, ge=1, le=168, description="Retención máxima de eventos.")
    max_events: int = Field(50000, ge=100, le=100000, description="Máximo de intentos en disco.")
    alert_threshold: int = Field(400, ge=2, le=10000, description="Claves distintas para alertar.")
    alert_window: int = Field(120, ge=1, le=600, description="Ventana de detección en segundos.")
    report_window: int = Field(300, ge=1, le=86400, description="Ventana del informe en segundos.")
    duration: float = Field(
        0, ge=0, le=604800, description="Parar tras estos segundos; 0 continuo."
    )

    @field_validator("host", "dashboard_host")
    @classmethod
    def literal_address(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("dashboard_host")
    @classmethod
    def private_dashboard(cls, value: str) -> str:
        if not ip_address(value).is_loopback:
            raise ValueError("El panel debe escuchar en loopback; usa un túnel SSH administrativo")
        return value

    @model_validator(mode="after")
    def consistent_limits(self):
        if self.max_per_ip > self.max_connections:
            raise ValueError("max_per_ip no puede superar max_connections")
        if self.report_window < self.alert_window:
            raise ValueError("report_window debe cubrir al menos alert_window")
        if self.report_window > self.retention_hours * 3600:
            raise ValueError("report_window no puede superar la retención")
        if self.alert_threshold > self.max_events:
            raise ValueError("max_events debe permitir alcanzar alert_threshold")
        return self


class SSHHoneypot(ServiceModule):
    id = "ssh-honeypot"
    name = "Honeypot SSH"
    description = "Señuelo SSH sin acceso, con panel privado de intentos y alertas."
    category = Category.INTEL
    InputModel = HoneypotInputs

    def target_of(self, inputs: HoneypotInputs) -> str:
        host = f"[{inputs.host}]" if ":" in inputs.host else inputs.host
        return f"ssh://{host}:{inputs.port}"

    async def run(self, inputs: HoneypotInputs, context: ServiceContext) -> None:
        from atalaya.services.honeypot import serve_honeypot

        await serve_honeypot(inputs, context)
