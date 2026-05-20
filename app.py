from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
import bcrypt

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"

# Conexión a SQL Server
conexion = pyodbc.connect(
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=MENDOZA;'
    'DATABASE=EXAMEN;'
    'Trusted_Connection=yes;'
)

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
        id_examen = request.args.get("id_examen")

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
                elif tipo == "vf" and respuesta.lower() == correcta.lower():
                    correctas += 1
                elif tipo == "abierta" and respuesta.strip().lower() == texto_correcto.strip().lower():
                    correctas += 1

            conexion.commit()

            # Calcular puntaje
            puntaje = (correctas / total) * 100

            # Guardar resultado
            cursor.execute("""
                INSERT INTO resultados (id_usuario, id_examen, puntaje)
                VALUES (?, ?, ?)
            """, (session["usuario_id"], id_examen, puntaje))
            conexion.commit()

            return render_template("resultado_examen.html", titulo=examen[0], puntaje=puntaje)

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

        return render_template("resolver_examen.html", titulo=examen[0], preguntas=preguntas_list)
    else:
        return redirect("/login")



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
