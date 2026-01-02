from fastapi import FastAPI, Header, HTTPException
from fastapi import FastAPI
import imaplib
import email
import os
import json
import base64
import re
from email.header import decode_header
from datetime import datetime, timedelta
from email.header import decode_header
from pydantic import BaseModel, Field, EmailStr

# =========================
# CONFIGURACIÓN
# =========================

API_KEY = os.getenv("API_KEY", "fd7be1d1-5cf2-4639-8685-9a4951826f90")

app = FastAPI()

IMAP_SERVER = os.getenv("IMAP_SERVER", "imap.gmail.com")

class RangoFechas(BaseModel):
    fecha_desde: str = Field(
        ...,
        description="Fecha inicio (YYYY-MM-DD, DD-MM-YYYY o DD/MM/YYYY)",
        example="2025-12-01"
    )
    fecha_hasta: str = Field(
        ...,
        description="Fecha fin (YYYY-MM-DD, DD-MM-YYYY o DD/MM/YYYY)",
        example="2025-12-31"
    )
    email: EmailStr = Field(
        ...,
        description="Correo electrónico a consultar",
        example="contabilidad@opticasavplus.com"
    )
    token_email: str = Field(
        ...,
        description="Token o contraseña de aplicación del correo",
        example="abcd..."
    )


def limpiar_texto(filename: str) -> str:
    if not filename:
        return ""

    # Quitar saltos de línea y espacios raros
    filename = filename.replace("\r", "").replace("\n", "").strip()

    # Quitar caracteres peligrosos para archivos
    filename = re.sub(r'[\\/*?:"<>|]', "_", filename)

    return filename

def fecha_a_imap(fecha_str):
    """
    Acepta:
    - '2025-12-01'

    Retorna:
    - '01-Dec-2025' (formato IMAP)
    """
    formatos = [
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y"
    ]

    for fmt in formatos:
        try:
            fecha = datetime.strptime(fecha_str, fmt)
            return fecha.strftime("%d-%b-%Y")
        except ValueError:
            continue
    raise ValueError(f"Formato de fecha no válido: {fecha_str}")

# =========================
def clean(text):
    return "".join(c if c.isalnum() else "_" for c in text)

def mostrar_json_en_consola(ruta_json):
    try:
        with open(ruta_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        print("CONTENIDO DEL JSON")
        print("=" * 70)
        print(json.dumps(data, indent=4, ensure_ascii=False))
        print("=" * 70)

    except json.JSONDecodeError:
        print("Error: JSON inválido:", ruta_json)

    except Exception as e:
        print("Error leyendo el archivo:", e)

def decode_mime_header(value):
    if not value:
        return ""

    decoded_parts = decode_header(value)
    texto = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            try:
                texto += part.decode(encoding or "utf-8")
            except (LookupError, UnicodeDecodeError):
                texto += part.decode("utf-8", errors="ignore")
        else:
            texto += part

    return texto.strip()

def mostrar_json_base64(payload_bytes):
    try:
        # Validar que sea JSON (decodificamos solo para validar)
        json_data = json.loads(payload_bytes.decode("utf-8", errors="strict"))

        # Volver a convertir a bytes normalizados
        json_bytes = json.dumps(
            json_data,
            ensure_ascii=False,
            separators=(",", ":")
        ).encode("utf-8")

        # Base64 encode
        base64_json = base64.b64encode(json_bytes).decode("utf-8")

        print("JSON EN BASE64")
        print("=" * 70)
        print(base64_json)
        print("=" * 70)

    except json.JSONDecodeError:
        print("El adjunto no es un JSON válido")

    except Exception as e:
        print("Error procesando JSON:", e)

# =========================
# PROCESAR CORREOS
# =========================

@app.post("/correos/json")
def obtener_correos_json(data: RangoFechas, x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API Key inválida")
    try:
        desde = fecha_a_imap(data.fecha_desde)
        hasta = fecha_a_imap(data.fecha_hasta)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    fecha_hasta_imap = (
        datetime.strptime(hasta, "%d-%b-%Y") + timedelta(days=1)
    ).strftime("%d-%b-%Y")

    try:
        imap = imaplib.IMAP4_SSL(IMAP_SERVER)
        imap.login(data.email, data.token_email)

    except imaplib.IMAP4.error as e:
        error_msg = str(e)

        if "AUTHENTICATIONFAILED" in error_msg.upper():
            raise HTTPException(
                status_code=401,
                detail="Credenciales del correo inválidas o token incorrecto"
            )
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Error IMAP: {error_msg}"
            )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error inesperado al conectar con el correo: {str(e)}"
        )
    imap.select("INBOX")

    status, messages = imap.search(
        None,
        f'(SINCE "{desde}" BEFORE "{fecha_hasta_imap}")'
    )

    email_ids = messages[0].split()
    resultados = []

    for mail_id in email_ids:
        #Ver si tiene adjuntos (rápido)
        status, data = imap.fetch(mail_id, "(BODYSTRUCTURE)")
        if status != "OK":
            continue

        body = data[0].decode().upper()
        if "ATTACHMENT" not in body and "APPLICATION" not in body:
            continue

        #Descargar correo completo SOLO si tiene adjuntos
        status, msg_data = imap.fetch(mail_id, "(RFC822)")
        if status != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])

        if not msg.is_multipart():
            continue

        subject = limpiar_texto(decode_mime_header(msg.get("Subject")))
        from_ = decode_mime_header(msg.get("From"))

        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", "")).lower()

            if "attachment" not in content_disposition:
                continue

            filename = limpiar_texto(part.get_filename() or "")

            if not filename.lower().endswith(".json"):
                continue

            payload = part.get_payload(decode=True)

            try:
                json_data = json.loads(payload.decode("utf-8"))
            except Exception:
                continue

            json_bytes = json.dumps(
                json_data,
                ensure_ascii=False,
                separators=(",", ":")
            ).encode("utf-8")

            json_base64 = base64.b64encode(json_bytes).decode("utf-8")
            resultados.append({
                "asunto": subject,
                "de": from_,
                "archivo": filename,
                "mail_id": mail_id,
                "json_base64": json_base64
            })

    imap.close()
    imap.logout()

    return {
        "total": len(resultados),
        "correos": resultados
    }