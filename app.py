from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pyodbc
import bcrypt
import datetime

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"

# Conexión a SQL Server
conexion = pyodbc.connect(
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=MENDOZA;'
    'DATABASE=EXAMEN;'
    'Trusted_Connection=yes;'
)


def columna_existe(tabla, columna):
    cursor = conexion.cursor()
    cursor.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = ? AND COLUMN_NAME = ?",
        (tabla, columna)
    )
    return cursor.fetchone() is not None


def asegurar_tabla_reportes():
    cursor = conexion.cursor()
    cursor.execute(
        """
        IF NOT EXISTS (
            SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'reporte_sospecha') AND type in (N'U')
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
    conexion.commit()

# 🔹 Ruta raíz
@app.route("/")
def inicio():
    return redirect(url_for("login"))

# 🔹 Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        usuario = request.form["usuario"]
        password = request.form["password"]

        cursor = conexion.cursor()
        cursor.execute("SELECT id_usuario, password_hash, rol FROM usuarios WHERE usuario = ?", (usuario,))
        fila = cursor.fetchone()

        if fila and bcrypt.checkpw(password.encode("utf-8"), fila[1].encode("utf-8")):
            session["usuario"] = usuario
            session["rol"] = fila[2]
            session["usuario_id"] = fila[0]
            return redirect(url_for("panel"))
        else:
            return render_template("login.html", error="Usuario o contraseña incorrecta")

    return render_template("login.html")

# 🔹 Registro________________________________________
# 🔹 Registro de docentes (solo admin)
@app.route("/registro_docente", methods=["GET", "POST"])
def registro_docente():
    if "usuario" in session and session.get("rol") == "admin":
        if request.method == "POST":
            nombre = request.form["nombre"]
            apellido = request.form["apellido"]
            usuario = request.form["usuario"]
            correo = request.form["correo"]
            password = request.form["password"]

            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            cursor = conexion.cursor()
            cursor.execute("""
                INSERT INTO usuarios (nombre, apellido, usuario, correo, password_hash, rol)
                VALUES (?, ?, ?, ?, ?, 'docente')
            """, (nombre, apellido, usuario, correo, password_hash))
            conexion.commit()

            return render_template("registro_docente.html", mensaje="Docente registrado correctamente")
        return render_template("registro_docente.html")
    else:
        return redirect("/login")

# 🔹 Registro de estudiantes (solo docente)
@app.route("/registro_estudiante", methods=["GET", "POST"])
def registro_estudiante():
    if "usuario" in session and session.get("rol") == "docente":
        if request.method == "POST":
            nombre = request.form["nombre"]
            apellido = request.form["apellido"]
            usuario = request.form["usuario"]
            correo = request.form["correo"]
            password = request.form["password"]

            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            cursor = conexion.cursor()
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

            conexion.commit()

            return render_template("registro_estudiante.html", mensaje="Estudiante registrado correctamente")
        return render_template("registro_estudiante.html")
    else:
        return redirect("/login")


# 🔹 Panel principal
@app.route("/panel")
def panel():
    if "usuario" in session:
        rol = session.get("rol")

        if rol == "admin":
            return render_template("panel_admin.html", usuario=session["usuario"], rol=rol)
        elif rol == "docente":
            return render_template("panel_docente.html", usuario=session["usuario"], rol=rol)
        elif rol == "estudiante":
            return render_template("panel_estudiante.html", usuario=session["usuario"], rol=rol)
        else:
            return redirect(url_for("login"))
    else:
        return redirect(url_for("login"))

# 🔹 Admin: Control de asistencia
@app.route("/admin_asistencia")
def admin_asistencia():
    if "usuario" in session and session.get("rol") == "admin":
        return render_template(
            "pagina_simple.html",
            title="Control de Asistencia",
            message="Funcionalidad en desarrollo. Aquí se gestionará la asistencia de los estudiantes.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Admin: Reportes
@app.route("/admin_reportes")
def admin_reportes():
    if "usuario" in session and session.get("rol") == "admin":
        return render_template(
            "pagina_simple.html",
            title="Reportes",
            message="Funcionalidad en desarrollo. Aquí se mostrará la información de reportes.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Admin: Seguridad
@app.route("/admin_seguridad")
def admin_seguridad():
    if "usuario" in session and session.get("rol") == "admin":
        return render_template(
            "pagina_simple.html",
            title="Seguridad",
            message="Funcionalidad en desarrollo. Aquí se mostrarán los controles de seguridad.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Admin: Redes
@app.route("/admin_redes")
def admin_redes():
    if "usuario" in session and session.get("rol") == "admin":
        return render_template(
            "pagina_simple.html",
            title="Redes",
            message="Funcionalidad en desarrollo. Aquí se gestionará la infraestructura de redes.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Admin: Usuarios
@app.route("/admin_usuarios")
def admin_usuarios():
    if "usuario" in session and session.get("rol") == "admin":
        cursor = conexion.cursor()
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
    return redirect(url_for("login"))

# 🔹 Admin: Monitoreo
@app.route("/admin_monitoreo")
def admin_monitoreo():
    if "usuario" in session and session.get("rol") == "admin":
        return render_template(
            "pagina_simple.html",
            title="Monitoreo",
            message="Funcionalidad en desarrollo. Aquí se visualizarán los datos de monitoreo.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Docente: Cursos
@app.route("/docente_cursos")
def docente_cursos():
    if "usuario" in session and session.get("rol") == "docente":
        cursor = conexion.cursor()
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
                "No se encontró la columna id_docente en la tabla usuarios. "
                "Se muestran todos los estudiantes registrados, pero ninguno está vinculado específicamente a tu curso."
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

        return render_template(
            "docente_cursos.html",
            estudiantes=estudiantes,
            info_message=info_message
        )
    return redirect(url_for("login"))

# 🔹 Docente: Asistencia
@app.route("/docente_asistencia")
def docente_asistencia():
    if "usuario" in session and session.get("rol") == "docente":
        return render_template(
            "pagina_simple.html",
            title="Asistencia Docente",
            message="Funcionalidad en desarrollo. Aquí se registrará y consultará la asistencia del curso.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Resultados estudiante
@app.route("/resultados_estudiante")
def resultados_estudiante():
    if "usuario" in session and session.get("rol") == "estudiante":
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT e.titulo, r.puntaje FROM resultados r JOIN examenes e ON r.id_examen = e.id_examen WHERE r.id_usuario = ?",
            (session["usuario_id"],)
        )
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
    return redirect(url_for("login"))

# 🔹 Asistencia estudiante
@app.route("/asistencia_estudiante")
def asistencia_estudiante():
    if "usuario" in session and session.get("rol") == "estudiante":
        return render_template(
            "pagina_simple.html",
            title="Asistencia Estudiante",
            message="Funcionalidad en desarrollo. Aquí se mostrará el registro de asistencia para el estudiante.",
            back_url=url_for("panel")
        )
    return redirect(url_for("login"))

# 🔹 Exámenes del docente
@app.route("/examenes_docente")
def examenes_docente():
    if "usuario" in session and session.get("rol") == "docente":
        cursor = conexion.cursor()
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
    else:
        return redirect("/login")

# 🔹 Eliminar examen
@app.route("/eliminar_examen", methods=["POST"])
def eliminar_examen():
    if "usuario" in session and session.get("rol") == "docente":
        id_examen = request.form.get("id_examen")
        cursor = conexion.cursor()

        # Eliminar datos relacionados primero para evitar errores de clave foránea
        cursor.execute("DELETE FROM respuestas_estudiante WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM resultados WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM preguntas WHERE id_examen = ?", (id_examen,))
        cursor.execute("DELETE FROM examenes WHERE id_examen = ? AND creado_por = ?", (id_examen, session["usuario_id"]))
        conexion.commit()

        return redirect(url_for("examenes_docente"))
    else:
        return redirect(url_for("login"))

# 🔹 Crear examen
@app.route("/crear_examen", methods=["POST"])
def crear_examen():
    if "usuario" in session and session.get("rol") == "docente":
        titulo = request.form["titulo"]
        descripcion = request.form["descripcion"]
        fecha = request.form["fecha"]
        num_preguntas = int(request.form["num_preguntas"])

        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO examenes (titulo, descripcion, tiempo_limite, fecha_creacion, creado_por, num_preguntas)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (titulo, descripcion, 60, fecha, session["usuario_id"], num_preguntas))
        conexion.commit()

        return redirect(url_for("examenes_docente"))
    else:
        return redirect("/login")


# 🔹 Página para configurar preguntas
@app.route("/configurar_preguntas", methods=["GET"])
def configurar_preguntas():
    if "usuario" in session and session.get("rol") == "docente":
        # Recuperar el id_examen desde la URL
        id_examen = request.args.get("id_examen")

        if not id_examen:
            # Si no se pasa id_examen, redirige a la lista de exámenes
            return redirect("/examenes_docente")

        cursor = conexion.cursor()
        cursor.execute("""
            SELECT id_examen, titulo, num_preguntas
            FROM examenes
            WHERE id_examen = ?
        """, (id_examen,))
        examen = cursor.fetchone()

        if examen:
            # Si num_preguntas es NULL, lo convertimos en 0 para evitar errores
            num_preguntas = examen[2] if examen[2] is not None else 0

            examen_data = {
                "id_examen": examen[0],
                "titulo": examen[1],
                "num_preguntas": num_preguntas
            }
            return render_template("configurar_preguntas.html", examen=examen_data)
        else:
            return redirect("/examenes_docente")
    else:
        return redirect("/login")


# 🔹 Guardar preguntas
@app.route("/guardar_preguntas", methods=["POST"])
def guardar_preguntas():
    if "usuario" in session and session.get("rol") == "docente":
        id_examen = request.form["id_examen"]
        num_preguntas = int(request.form["num_preguntas"])

        cursor = conexion.cursor()
        for i in range(num_preguntas):
            pregunta = request.form.get(f"pregunta_{i}")
            tipo = request.form.get(f"tipo_{i}")
            opcion_a = request.form.get(f"opcion_a_{i}")
            opcion_b = request.form.get(f"opcion_b_{i}")
            opcion_c = request.form.get(f"opcion_c_{i}")
            opcion_d = request.form.get(f"opcion_d_{i}")
            respuesta_correcta = request.form.get(f"respuesta_correcta_{i}")
            respuesta_texto = request.form.get(f"respuesta_texto_{i}")

            cursor.execute("""
                INSERT INTO preguntas (id_examen, tipo_pregunta, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (id_examen, tipo, pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto))
        conexion.commit()

        return redirect("/examenes_docente")
    else:
        return redirect("/login")

# VER PREGUNTAS__________
@app.route("/ver_preguntas", methods=["GET"])
def ver_preguntas():
    if "usuario" in session and session.get("rol") == "docente":
        id_examen = request.args.get("id_examen")

        if not id_examen:
            return redirect("/examenes_docente")

        cursor = conexion.cursor()
        cursor.execute("""
            SELECT pregunta, tipo_pregunta, opcion_a, opcion_b, opcion_c, opcion_d, respuesta_correcta, respuesta_texto
            FROM preguntas
            WHERE id_examen = ?
        """, (id_examen,))
        preguntas = cursor.fetchall()

        cursor.execute("SELECT titulo FROM examenes WHERE id_examen = ?", (id_examen,))
        titulo = cursor.fetchone()[0]

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

        return render_template("ver_preguntas.html", titulo=titulo, preguntas=preguntas_list)
    else:
        return redirect("/login")
    
# EXAMEN DEL ESTUDIANTE___________________
# 🔹 Ver examen como estudiante
@app.route("/resolver_examen", methods=["GET", "POST"])
def resolver_examen():
    if "usuario" in session and session.get("rol") == "estudiante":
        id_examen = request.args.get("id_examen") or request.form.get("id_examen")

        cursor = conexion.cursor()
        cursor.execute("""
            SELECT titulo FROM examenes WHERE id_examen = ?
        """, (id_examen,))
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
                respuesta = request.form.get(f"respuesta_{id_pregunta}")

                # Guardar respuesta del estudiante
                cursor.execute("""
                    INSERT INTO respuestas_estudiante (id_usuario, id_examen, id_pregunta, respuesta)
                    VALUES (?, ?, ?, ?)
                """, (session["usuario_id"], id_examen, id_pregunta, respuesta))

                # Comparar con la respuesta correcta
                correcta = p[7]
                texto_correcto = p[8]

                if tipo == "opcion_multiple" and respuesta == correcta:
                    correctas += 1
                elif tipo == "vf" and respuesta and respuesta.lower() == correcta.lower():
                    correctas += 1
                elif tipo == "abierta" and respuesta and respuesta.strip().lower() == texto_correcto.strip().lower():
                    correctas += 1

            conexion.commit()

            # Calcular puntaje
            puntaje = (correctas / total) * 100 if total > 0 else 0

            # Guardar resultado
            cursor.execute("""
                INSERT INTO resultados (id_usuario, id_examen, puntaje)
                VALUES (?, ?, ?)
            """, (session["usuario_id"], id_examen, puntaje))
            conexion.commit()

            return render_template("resultado_examen.html", titulo=examen[0], puntaje=puntaje, auto_submit=auto_submit)

        # Mostrar preguntas en la plantilla
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

        if request.method == "GET":
            if "suspicious_counts" not in session:
                session["suspicious_counts"] = {}
            session["suspicious_counts"][id_examen] = 0

        return render_template("resolver_examen.html", titulo=examen[0], preguntas=preguntas_list, id_examen=id_examen)
    else:
        return redirect("/login")


@app.route("/reportar_sospecha", methods=["POST"])
def reportar_sospecha():
    if "usuario" not in session or session.get("rol") != "estudiante":
        return jsonify({"ok": False}), 403

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
    contador_sesion = examen_counts.get(id_examen, 0)

    # Si ya llegó a 3, rechazar nuevo reporte
    if contador_sesion >= 3:
        return jsonify({"ok": True, "close_exam": True, "contador": 3})

    now = int(datetime.datetime.utcnow().timestamp() * 1000)
    last_entries = exam_last.get(id_examen, [])

    duplicate = False
    for last_entry in last_entries:
        last_time = last_entry.get("timestamp", 0)
        last_type = last_entry.get("tipo")
        if last_time and now - last_time < 3000 and last_type == tipo:
            duplicate = True
            break

    if duplicate:
        return jsonify({"ok": True, "close_exam": contador_sesion >= 3, "contador": contador_sesion})

    # Incrementar contador solo si no es duplicado
    contador_sesion += 1
    examen_counts[id_examen] = contador_sesion
    session["suspicious_counts"] = examen_counts
    
    if id_examen not in exam_last:
        exam_last[id_examen] = []
    exam_last[id_examen].append({
        "timestamp": now,
        "tipo": tipo
    })
    exam_last[id_examen] = exam_last[id_examen][-5:]
    session["suspicious_last"] = exam_last

    close_exam = contador_sesion >= 3

    asegurar_tabla_reportes()
    cursor = conexion.cursor()
    cursor.execute(
        "SELECT id_reporte, contador FROM reporte_sospecha WHERE id_usuario = ? AND id_examen = ?",
        (session["usuario_id"], id_examen)
    )
    fila = cursor.fetchone()

    if fila:
        id_reporte, contador = fila
        contador += 1
        estado = "cerrado" if contador >= 3 else "abierto"
        cursor.execute(
            "UPDATE reporte_sospecha SET contador = ?, tipo_evento = ?, descripcion = ?, estado = ?, fecha = GETDATE() WHERE id_reporte = ?",
            (contador, tipo, descripcion, estado, id_reporte)
        )
    else:
        contador = 1
        estado = "cerrado" if contador >= 3 else "abierto"
        cursor.execute(
            "INSERT INTO reporte_sospecha (id_usuario, id_examen, tipo_evento, descripcion, contador, estado) VALUES (?, ?, ?, ?, ?, ?)",
            (session["usuario_id"], id_examen, tipo, descripcion, contador, estado)
        )

    conexion.commit()
    return jsonify({"ok": True, "close_exam": close_exam, "contador": contador_sesion})


@app.route("/docente_reportes")
def docente_reportes():
    if "usuario" in session and session.get("rol") == "docente":
        asegurar_tabla_reportes()
        cursor = conexion.cursor()

        if columna_existe("usuarios", "id_docente"):
            cursor.execute(
                """
                SELECT r.id_reporte, u.nombre + ' ' + u.apellido AS estudiante, u.usuario, e.titulo, r.tipo_evento, r.descripcion, r.contador, r.estado, r.fecha
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
                SELECT r.id_reporte, u.nombre + ' ' + u.apellido AS estudiante, u.usuario, e.titulo, r.tipo_evento, r.descripcion, r.contador, r.estado, r.fecha
                FROM reporte_sospecha r
                JOIN usuarios u ON r.id_usuario = u.id_usuario
                LEFT JOIN examenes e ON r.id_examen = e.id_examen
                ORDER BY r.fecha DESC
                """
            )

        reportes = cursor.fetchall()
        return render_template("docente_reportes.html", reportes=reportes)

    return redirect(url_for("login"))


# VER EXAMENES_______________
# 🔹 Página para ver exámenes disponibles (estudiante)
@app.route("/examenes_estudiante")
def examenes_estudiante():
    if "usuario" in session and session.get("rol") == "estudiante":
        cursor = conexion.cursor()
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
    else:
        return redirect("/login")



# 🔹 Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# 🔹 Ejecutar servidor
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
