import os
import bcrypt
import datetime
import logging
from functools import wraps
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, flash
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyodbc

# ───────────────────────────────────────────────
# CARGAR VARIABLES DE ENTORNO
# ───────────────────────────────────────────────
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY no está configurada en las variables de entorno")

# ───────────────────────────────────────────────
# CONFIGURACIÓN DE SEGURIDAD
# ───────────────────────────────────────────────
csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ───────────────────────────────────────────────
# CONFIGURACIÓN DE BASE DE DATOS
# ───────────────────────────────────────────────
def get_db_connection():
    """
    Crea una nueva conexión a la base de datos con manejo de errores.
    """
    try:
        driver = os.environ.get('DB_DRIVER', 'ODBC Driver 17 for SQL Server')
        server = os.environ.get('DB_SERVER', 'MENDOZA')
        database = os.environ.get('DB_NAME', 'EXAMEN')
        trusted = os.environ.get('DB_TRUSTED', 'yes').lower() == 'yes'
        user = os.environ.get('DB_USER', '')
        password = os.environ.get('DB_PASSWORD', '')

        if trusted:
            conn_str = (
                f'DRIVER={{{driver}}};'
                f'SERVER={server};'
                f'DATABASE={database};'
                f'Trusted_Connection=yes;'
            )
        else:
            conn_str = (
                f'DRIVER={{{driver}}};'
                f'SERVER={server};'
                f'DATABASE={database};'
                f'UID={user};'
                f'PWD={password};'
            )

        conn = pyodbc.connect(conn_str, timeout=10)
        return conn
    except pyodbc.Error as e:
        logger.error(f"Error de conexión a BD: {e}")
        raise
    except Exception as e:
        logger.error(f"Error inesperado al conectar BD: {e}")
        raise


def handle_db_errors(f):
    """
    Decorador para manejar errores de base de datos en rutas.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except pyodbc.Error as e:
            logger.error(f"Error de BD en {f.__name__}: {e}")
            return render_template(
                "error.html",
                title="Error de Base de Datos",
                message="Hubo un problema al conectar con la base de datos. Intente nuevamente más tarde."
            ), 500
        except Exception as e:
            logger.error(f"Error inesperado en {f.__name__}: {e}")
            return render_template(
                "error.html",
                title="Error Inesperado",
                message="Ocurrió un error inesperado. Contacte al administrador."
            ), 500
    return decorated


def role_required(*roles):
    """
    Decorador para verificar roles permitidos.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if "usuario" not in session:
                flash("Debe iniciar sesión para acceder.", "warning")
                return redirect(url_for("login"))
            if session.get("rol") not in roles:
                flash("No tiene permisos para acceder a esta sección.", "danger")
                return redirect(url_for("panel"))
            return f(*args, **kwargs)
        return decorated
    return decorator


def columna_existe(tabla, columna):
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
                (tabla, columna)
            )
            return cursor.fetchone() is not None
    except Exception as e:
        logger.error(f"Error verificando columna {columna} en {tabla}: {e}")
        return False


def asegurar_tabla_reportes():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                IF NOT EXISTS (
                    SELECT * FROM sys.objects 
                    WHERE object_id = OBJECT_ID(N'reporte_sospecha') AND type in (N'U')
                )
                CREATE TABLE reporte_sospecha (
                    id_reporte INT IDENTITY(1,1) PRIMARY KEY,
                    id_usuario INT,
                    id_examen INT,
                    tipo_evento NVARCHAR(100),
                    descripcion NVARCHAR(500),
                    contador INT,
                    estado NVARCHAR(50),
                    fecha DATETIME DEFAULT GETDATE()
                )
                """
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Error asegurando tabla reportes: {e}")


# ───────────────────────────────────────────────
# RUTAS DE AUTENTICACIÓN
# ───────────────────────────────────────────────
@app.route("/")
def inicio():
    return redirect(url_for("login"))



# _______________LOGIN________________

@app.route("/login", methods=["GET", "POST"])
@handle_db_errors
def login():
    # Inicializar contador de intentos fallidos en sesión
    if "login_attempts" not in session:
        session["login_attempts"] = 0
        session["login_blocked_until"] = 0
    
    # Verificar si está bloqueado
    ahora = datetime.datetime.now().timestamp()
    bloqueado_hasta = session.get("login_blocked_until", 0)
    tiempo_restante = int(bloqueado_hasta - ahora)
    
    if tiempo_restante > 0:
        # Está bloqueado, mostrar login con contador
        return render_template("login.html", bloqueo_restante=tiempo_restante)
    
    # Si ya pasó el bloqueo, resetear contador
    if bloqueado_hasta > 0 and tiempo_restante <= 0:
        session["login_attempts"] = 0
        session["login_blocked_until"] = 0
    
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")
        
        # Verificar de nuevo si está bloqueado (por si acaso)
        if session.get("login_blocked_until", 0) > ahora:
            tiempo_restante = int(session["login_blocked_until"] - ahora)
            return render_template("login.html", bloqueo_restante=tiempo_restante)

        if not usuario or not password:
            return render_template("login.html", error="Usuario y contraseña son obligatorios")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id_usuario, password_hash, rol FROM usuarios WHERE usuario = ?",
                (usuario,)
            )
            fila = cursor.fetchone()

        if fila and bcrypt.checkpw(password.encode("utf-8"), fila[1].encode("utf-8")):
            # Login exitoso: resetear contador
            session["login_attempts"] = 0
            session["login_blocked_until"] = 0
            session["usuario"] = usuario
            session["rol"] = fila[2]
            session["usuario_id"] = fila[0]
            logger.info(f"Login exitoso: {usuario} (rol: {fila[2]})")
            return redirect(url_for("panel"))
        else:
            # Login fallido: incrementar contador
            session["login_attempts"] = session.get("login_attempts", 0) + 1
            intentos = session["login_attempts"]
            
            logger.warning(f"Intento de login fallido #{intentos}: {usuario} desde {request.remote_addr}")
            
            # Si llega a 3 intentos, bloquear por 60 segundos
            if intentos >= 3:
                session["login_blocked_until"] = ahora + 60
                logger.warning(f"Usuario bloqueado por 60 segundos: {request.remote_addr}")
                return render_template("login.html", bloqueo_restante=60)
            
            return render_template("login.html", error=f"Usuario o contraseña incorrecta (intento {intentos}/3)")

    return render_template("login.html")

@app.route("/logout")
def logout():
    usuario = session.get("usuario", "anónimo")
    session.clear()
    logger.info(f"Logout: {usuario}")
    return redirect(url_for("login"))


# ───────────────────────────────────────────────
# PANELES POR ROL
# ───────────────────────────────────────────────
@app.route("/panel")
def panel():
    if "usuario" not in session:
        return redirect(url_for("login"))

    rol = session.get("rol")
    usuario = session.get("usuario")

    if rol == "admin":
        return render_template("panel_admin.html", usuario=usuario, rol=rol)
    elif rol == "docente":
        return render_template("panel_docente.html", usuario=usuario, rol=rol)
    elif rol == "estudiante":
        return render_template("panel_estudiante.html", usuario=usuario, rol=rol)
    else:
        session.clear()
        return redirect(url_for("login"))


# ───────────────────────────────────────────────
# REGISTRO DE USUARIOS
# ───────────────────────────────────────────────
@app.route("/registro_docente", methods=["GET", "POST"])
@role_required("admin")
@handle_db_errors
def registro_docente():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        apellido = request.form.get("apellido", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "")

        if not all([nombre, apellido, usuario, correo, password]):
            return render_template("registro_docente.html", mensaje="Todos los campos son obligatorios")

        if len(password) < 6:
            return render_template("registro_docente.html", mensaje="La contraseña debe tener al menos 6 caracteres")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Verificar si el usuario ya existe
            cursor.execute("SELECT id_usuario FROM usuarios WHERE usuario = ?", (usuario,))
            if cursor.fetchone():
                return render_template("registro_docente.html", mensaje="El usuario ya existe")

            cursor.execute("""
                INSERT INTO usuarios (nombre, apellido, usuario, correo, password_hash, rol)
                VALUES (?, ?, ?, ?, ?, 'docente')
            """, (nombre, apellido, usuario, correo, password_hash))
            conn.commit()

        logger.info(f"Docente registrado: {usuario} por admin {session['usuario']}")
        flash("Docente registrado correctamente", "success")
        return redirect(url_for("admin_usuarios"))

    return render_template("registro_docente.html")


@app.route("/registro_estudiante", methods=["GET", "POST"])
@role_required("docente")
@handle_db_errors
def registro_estudiante():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        apellido = request.form.get("apellido", "").strip()
        usuario = request.form.get("usuario", "").strip()
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "")

        if not all([nombre, apellido, usuario, correo, password]):
            return render_template("registro_estudiante.html", mensaje="Todos los campos son obligatorios")

        if len(password) < 6:
            return render_template("registro_estudiante.html", mensaje="La contraseña debe tener al menos 6 caracteres")

        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id_usuario FROM usuarios WHERE usuario = ?", (usuario,))
            if cursor.fetchone():
                return render_template("registro_estudiante.html", mensaje="El usuario ya existe")

            if columna_existe("usuarios", "id_docente"):
                cursor.execute("""
                    INSERT INTO usuarios (nombre, apellido, usuario, correo, password_hash, rol, id_docente)
                    VALUES (?, ?, ?, ?, ?, 'estudiante', ?)
                """, (nombre, apellido, usuario, correo, password_hash, session["usuario_id"]))
            else:
                cursor.execute("""
                    INSERT INTO usuarios (nombre, apellido, usuario, correo, password_hash, rol)
                    VALUES (?, ?, ?, ?, ?, 'estudiante')
                """, (nombre, apellido, usuario, correo, password_hash))
            conn.commit()

        logger.info(f"Estudiante registrado: {usuario} por docente {session['usuario']}")
        flash("Estudiante registrado correctamente", "success")
        return redirect(url_for("docente_cursos"))

    return render_template("registro_estudiante.html")


# ───────────────────────────────────────────────
# ADMINISTRADOR
# ───────────────────────────────────────────────
@app.route("/admin_asistencia")
@role_required("admin")
def admin_asistencia():
    return render_template(
        "pagina_simple.html",
        title="Control de Asistencia",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


@app.route("/admin_reportes")
@role_required("admin")
def admin_reportes():
    return render_template(
        "pagina_simple.html",
        title="Reportes",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


@app.route("/admin_seguridad")
@role_required("admin")
def admin_seguridad():
    return render_template(
        "pagina_simple.html",
        title="Seguridad",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


@app.route("/admin_redes")
@role_required("admin")
def admin_redes():
    return render_template(
        "pagina_simple.html",
        title="Redes",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


@app.route("/admin_usuarios")
@role_required("admin")
@handle_db_errors
def admin_usuarios():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id_usuario, nombre, apellido, usuario, correo, rol FROM usuarios")
        usuarios = cursor.fetchall()

    headers = ["ID", "Nombre", "Apellido", "Usuario", "Correo", "Rol"]
    rows = [list(u) for u in usuarios]

    return render_template(
        "pagina_simple.html",
        title="Usuarios",
        message="Listado de usuarios registrados en el sistema.",
        back_url=url_for("panel"),
        headers=headers,
        rows=rows
    )


@app.route("/admin_monitoreo")
@role_required("admin")
def admin_monitoreo():
    return render_template(
        "pagina_simple.html",
        title="Monitoreo",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


# ───────────────────────────────────────────────
# DOCENTE
# ───────────────────────────────────────────────
@app.route("/docente_cursos")
@role_required("docente")
@handle_db_errors
def docente_cursos():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if columna_existe("usuarios", "id_docente"):
            cursor.execute(
                "SELECT id_usuario, nombre, apellido, usuario, correo FROM usuarios WHERE rol = 'estudiante' AND id_docente = ?",
                (session["usuario_id"],)
            )
            info_message = ""
        else:
            cursor.execute(
                "SELECT id_usuario, nombre, apellido, usuario, correo FROM usuarios WHERE rol = 'estudiante'"
            )
            info_message = (
                "No se encontró la columna id_docente. "
                "Se muestran todos los estudiantes."
            )

        estudiantes = []
        for est in cursor.fetchall():
            estudiantes.append({
                "id_usuario": est[0],
                "nombre": est[1],
                "apellido": est[2],
                "usuario": est[3],
                "correo": est[4]
            })

    return render_template("docente_cursos.html", estudiantes=estudiantes, info_message=info_message)


@app.route("/docente_asistencia")
@role_required("docente")
def docente_asistencia():
    return render_template(
        "pagina_simple.html",
        title="Asistencia Docente",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


@app.route("/docente_reportes")
@role_required("docente")
@handle_db_errors
def docente_reportes():
    asegurar_tabla_reportes()
    with get_db_connection() as conn:
        cursor = conn.cursor()

        if columna_existe("usuarios", "id_docente"):
            cursor.execute(
                """
                SELECT r.id_reporte, u.nombre + ' ' + u.apellido AS estudiante, u.usuario, 
                       e.titulo, r.tipo_evento, r.descripcion, r.contador, r.estado, r.fecha
                FROM reporte_sospecha r
                JOIN usuarios u ON r.id_usuario = u.id_usuario
                LEFT JOIN examenes e ON r.id_examen = e.id_examen
                WHERE u.id_docente = ?
                ORDER BY r.fecha DESC
                """,
                (session["usuario_id"],)
            )
        else:
            cursor.execute(
                """
                SELECT r.id_reporte, u.nombre + ' ' + u.apellido AS estudiante, u.usuario, 
                       e.titulo, r.tipo_evento, r.descripcion, r.contador, r.estado, r.fecha
                FROM reporte_sospecha r
                JOIN usuarios u ON r.id_usuario = u.id_usuario
                LEFT JOIN examenes e ON r.id_examen = e.id_examen
                ORDER BY r.fecha DESC
                """
            )

        reportes = cursor.fetchall()

    return render_template("docente_reportes.html", reportes=reportes)


# ───────────────────────────────────────────────
# EXÁMENES (DOCENTE)
# ───────────────────────────────────────────────
@app.route("/examenes_docente")
@role_required("docente")
@handle_db_errors
def examenes_docente():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id_examen, titulo, descripcion, fecha_creacion, num_preguntas
            FROM examenes
            WHERE creado_por = ?
        """, (session["usuario_id"],))
        examenes = cursor.fetchall()

    examenes_list = []
    for e in examenes:
        examenes_list.append({
            "id_examen": e[0],
            "titulo": e[1],
            "descripcion": e[2],
            "fecha": e[3],
            "num_preguntas": e[4]
        })

    return render_template("examenes_docente.html", examenes=examenes_list)


@app.route("/crear_examen", methods=["POST"])
@role_required("docente")
@handle_db_errors
def crear_examen():
    titulo = request.form.get("titulo", "").strip()
    descripcion = request.form.get("descripcion", "").strip()
    fecha = request.form.get("fecha")
    num_preguntas = request.form.get("num_preguntas", type=int)

    if not all([titulo, descripcion, fecha]) or num_preguntas is None or num_preguntas < 1:
        flash("Todos los campos son obligatorios y la cantidad de preguntas debe ser al menos 1", "danger")
        return redirect(url_for("examenes_docente"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO examenes (titulo, descripcion, tiempo_limite, fecha_creacion, creado_por, num_preguntas)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (titulo, descripcion, 60, fecha, session["usuario_id"], num_preguntas))
        conn.commit()

    logger.info(f"Examen creado: '{titulo}' por docente {session['usuario']}")
    flash("Examen creado correctamente", "success")
    return redirect(url_for("examenes_docente"))


@app.route("/eliminar_examen", methods=["POST"])
@role_required("docente")
@handle_db_errors
def eliminar_examen():
    id_examen = request.form.get("id_examen", type=int)
    if not id_examen:
        flash("ID de examen no válido", "danger")
        return redirect(url_for("examenes_docente"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM respuestas_estudiante WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM resultados WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM preguntas WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM examenes WHERE id_examen = ? AND creado_por = ?", 
                      (id_examen, session["usuario_id"]))
        conn.commit()

    logger.info(f"Examen eliminado: ID {id_examen} por docente {session['usuario']}")
    flash("Examen eliminado correctamente", "success")
    return redirect(url_for("examenes_docente"))


@app.route("/configurar_preguntas", methods=["GET"])
@role_required("docente")
@handle_db_errors
def configurar_preguntas():
    id_examen = request.args.get("id_examen", type=int)
    if not id_examen:
        return redirect(url_for("examenes_docente"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id_examen, titulo, num_preguntas
            FROM examenes
            WHERE id_examen = ? AND creado_por = ?
        """, (id_examen, session["usuario_id"]))
        examen = cursor.fetchone()

    if not examen:
        flash("Examen no encontrado o no tienes permisos", "danger")
        return redirect(url_for("examenes_docente"))

    examen_data = {
        "id_examen": examen[0],
        "titulo": examen[1],
        "num_preguntas": examen[2] if examen[2] is not None else 0
    }
    return render_template("configurar_preguntas.html", examen=examen_data)


@app.route("/guardar_preguntas", methods=["POST"])
@role_required("docente")
@handle_db_errors
def guardar_preguntas():
    id_examen = request.form.get("id_examen", type=int)
    num_preguntas = request.form.get("num_preguntas", type=int)

    if not id_examen or num_preguntas is None:
        flash("Datos del examen no válidos", "danger")
        return redirect(url_for("examenes_docente"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        for i in range(num_preguntas):
            pregunta = request.form.get(f"pregunta_{i}", "").strip()
            tipo = request.form.get(f"tipo_{i}")
            opcion_a = request.form.get(f"opcion_a_{i}", "").strip()
            opcion_b = request.form.get(f"opcion_b_{i}", "").strip()
            opcion_c = request.form.get(f"opcion_c_{i}", "").strip()
            opcion_d = request.form.get(f"opcion_d_{i}", "").strip()
            respuesta_correcta = request.form.get(f"respuesta_correcta_{i}", "").strip()
            respuesta_texto = request.form.get(f"respuesta_texto_{i}", "").strip()

            if not pregunta or not tipo:
                continue

            cursor.execute("""
                INSERT INTO preguntas (id_examen, tipo_pregunta, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (id_examen, tipo, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto))
        conn.commit()

    logger.info(f"Preguntas guardadas para examen ID {id_examen}")
    flash("Preguntas guardadas correctamente", "success")
    return redirect(url_for("examenes_docente"))


@app.route("/ver_preguntas", methods=["GET"])
@role_required("docente")
@handle_db_errors
def ver_preguntas():
    id_examen = request.args.get("id_examen", type=int)
    if not id_examen:
        return redirect(url_for("examenes_docente"))

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT pregunta, tipo_pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto
            FROM preguntas
            WHERE id_examen = ?
        """, (id_examen,))
        preguntas = cursor.fetchall()

        cursor.execute("SELECT titulo FROM examenes WHERE id_examen = ? AND creado_por = ?", 
                      (id_examen, session["usuario_id"]))
        titulo_row = cursor.fetchone()

    if not titulo_row:
        flash("Examen no encontrado", "danger")
        return redirect(url_for("examenes_docente"))

    preguntas_list = []
    for p in preguntas:
        preguntas_list.append({
            "pregunta": p[0],
            "tipo": p[1],
            "a": p[2],
            "b": p[3],
            "c": p[4],
            "d": p[5],
            "correcta": p[6],
            "texto": p[7]
        })

    return render_template("ver_preguntas.html", titulo=titulo_row[0], preguntas=preguntas_list)


# ───────────────────────────────────────────────
# ESTUDIANTE
# ───────────────────────────────────────────────
@app.route("/examenes_estudiante")
@role_required("estudiante")
@handle_db_errors
def examenes_estudiante():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id_examen, titulo, descripcion, fecha_creacion, num_preguntas
            FROM examenes
        """)
        examenes = cursor.fetchall()

    examenes_list = []
    for e in examenes:
        examenes_list.append({
            "id_examen": e[0],
            "titulo": e[1],
            "descripcion": e[2],
            "fecha": e[3],
            "num_preguntas": e[4]
        })

    return render_template("examenes_estudiante.html", examenes=examenes_list)


@app.route("/resolver_examen", methods=["GET", "POST"])
@role_required("estudiante")
@handle_db_errors
def resolver_examen():
    id_examen = request.args.get("id_examen", type=int) or request.form.get("id_examen", type=int)
    if not id_examen:
        return redirect(url_for("examenes_estudiante"))

    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Verificar si ya resolvió este examen
        cursor.execute("""
            SELECT id_resultado FROM resultados 
            WHERE id_usuario = ? AND id_examen = ?
        """, (session["usuario_id"], id_examen))
        if cursor.fetchone() and request.method == "GET":
            flash("Ya has resuelto este examen. No puedes repetirlo.", "warning")
            return redirect(url_for("resultados_estudiante"))

        cursor.execute("SELECT titulo FROM examenes WHERE id_examen = ?", (id_examen,))
        examen = cursor.fetchone()

        cursor.execute("""
            SELECT id_pregunta, pregunta, tipo_pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto
            FROM preguntas
            WHERE id_examen = ?
        """, (id_examen,))
        preguntas = cursor.fetchall()

        if request.method == "POST":
            correctas = 0
            total = len(preguntas)
            auto_submit = request.form.get("auto_submit") == "1"

            for p in preguntas:
                id_pregunta = p[0]
                tipo = p[2]
                respuesta = request.form.get(f"respuesta_{id_pregunta}", "")

                cursor.execute("""
                    INSERT INTO respuestas_estudiante (id_usuario, id_examen, id_pregunta, respuesta)
                    VALUES (?, ?, ?, ?)
                """, (session["usuario_id"], id_examen, id_pregunta, respuesta))

                correcta = p[7]
                texto_correcto = p[8]

                if tipo == "seleccion" and respuesta == correcta:
                    correctas += 1
                elif tipo == "vf" and respuesta and respuesta.lower() == (correcta or "").lower():
                    correctas += 1
                elif tipo == "abierta" and respuesta and texto_correcto and respuesta.strip().lower() == texto_correcto.strip().lower():
                    correctas += 1

            conn.commit()

            puntaje = (correctas / total) * 100 if total > 0 else 0

            cursor.execute("""
                INSERT INTO resultados (id_usuario, id_examen, puntaje)
                VALUES (?, ?, ?)
            """, (session["usuario_id"], id_examen, puntaje))
            conn.commit()

            logger.info(f"Examen resuelto: ID {id_examen} por estudiante {session['usuario']} - Puntaje: {puntaje:.2f}%")
            return render_template("resultado_examen.html", titulo=examen[0], puntaje=puntaje, auto_submit=auto_submit)

        preguntas_list = []
        for p in preguntas:
            preguntas_list.append({
                "id": p[0],
                "pregunta": p[1],
                "tipo": p[2],
                "a": p[3],
                "b": p[4],
                "c": p[5],
                "d": p[6]
            })

        if "suspicious_counts" not in session:
            session["suspicious_counts"] = {}
        session["suspicious_counts"][str(id_examen)] = 0

    return render_template("resolver_examen.html", titulo=examen[0], preguntas=preguntas_list, id_examen=id_examen)


@app.route("/resultados_estudiante")
@role_required("estudiante")
@handle_db_errors
def resultados_estudiante():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT e.titulo, r.puntaje 
            FROM resultados r 
            JOIN examenes e ON r.id_examen = e.id_examen 
            WHERE r.id_usuario = ?
        """, (session["usuario_id"],))
        resultados = cursor.fetchall()

    headers = ["Examen", "Puntaje"]
    rows = [[r[0], f"{r[1]:.2f}%"] for r in resultados]
    message = "Estos son tus resultados guardados." if rows else "Aún no tienes resultados registrados."

    return render_template(
        "pagina_simple.html",
        title="Resultados del estudiante",
        message=message,
        back_url=url_for("panel"),
        headers=headers,
        rows=rows
    )


@app.route("/asistencia_estudiante")
@role_required("estudiante")
def asistencia_estudiante():
    return render_template(
        "pagina_simple.html",
        title="Asistencia Estudiante",
        message="Funcionalidad en desarrollo.",
        back_url=url_for("panel")
    )


# ───────────────────────────────────────────────
# REPORTAR SOSPECHA (ANTI-TRAMPA)
# ───────────────────────────────────────────────
@app.route("/reportar_sospecha", methods=["POST"])
@role_required("estudiante")
def reportar_sospecha():
    data = request.get_json(silent=True) or {}
    id_examen = data.get("id_examen")
    tipo = data.get("tipo")
    descripcion = data.get("mensaje")

    if not id_examen or not tipo:
        return jsonify({"ok": False, "error": "Datos incompletos"}), 400

    if "suspicious_counts" not in session:
        session["suspicious_counts"] = {}
    if "suspicious_last" not in session:
        session["suspicious_last"] = {}

    examen_counts = session["suspicious_counts"]
    exam_last = session["suspicious_last"]
    contador_sesion = examen_counts.get(str(id_examen), 0)

    if contador_sesion >= 3:
        return jsonify({"ok": True, "close_exam": True, "contador": 3})

    now = int(datetime.datetime.utcnow().timestamp() * 1000)
    last_entries = exam_last.get(str(id_examen), [])

    duplicate = False
    for last_entry in last_entries:
        if now - last_entry.get("timestamp", 0) < 3000 and last_entry.get("tipo") == tipo:
            duplicate = True
            break

    if duplicate:
        return jsonify({"ok": True, "close_exam": contador_sesion >= 3, "contador": contador_sesion})

    contador_sesion += 1
    examen_counts[str(id_examen)] = contador_sesion
    session["suspicious_counts"] = examen_counts

    exam_last.setdefault(str(id_examen), []).append({"timestamp": now, "tipo": tipo})
    exam_last[str(id_examen)] = exam_last[str(id_examen)][-5:]
    session["suspicious_last"] = exam_last

    close_exam = contador_sesion >= 3

    try:
        asegurar_tabla_reportes()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id_reporte, contador FROM reporte_sospecha WHERE id_usuario = ? AND id_examen = ?",
                (session["usuario_id"], id_examen)
            )
            fila = cursor.fetchone()

            if fila:
                nuevo_contador = fila[1] + 1
                estado = "cerrado" if nuevo_contador >= 3 else "abierto"
                cursor.execute(
                    "UPDATE reporte_sospecha SET contador = ?, tipo_evento = ?, descripcion = ?, estado = ?, fecha = GETDATE() WHERE id_reporte = ?",
                    (nuevo_contador, tipo, descripcion, estado, fila[0])
                )
            else:
                estado = "cerrado" if contador_sesion >= 3 else "abierto"
                cursor.execute(
                    "INSERT INTO reporte_sospecha (id_usuario, id_examen, tipo_evento, descripcion, contador, estado) VALUES (?, ?, ?, ?, ?, ?)",
                    (session["usuario_id"], id_examen, tipo, descripcion, contador_sesion, estado)
                )
            conn.commit()
    except Exception as e:
        logger.error(f"Error guardando reporte de sospecha: {e}")
        return jsonify({"ok": False, "error": "Error al guardar reporte"}), 500

    logger.warning(f"Sospecha reportada: {tipo} - Examen {id_examen} - Estudiante {session['usuario']} - Contador: {contador_sesion}")
    return jsonify({"ok": True, "close_exam": close_exam, "contador": contador_sesion})


# ───────────────────────────────────────────────
# EJECUCIÓN
# ───────────────────────────────────────────────
if __name__ == "__main__":
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)