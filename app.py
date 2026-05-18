from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
import bcrypt

app = Flask(__name__)
app.secret_key = "clave_secreta_segura"  # Necesaria para manejar sesiones

# Conexión a SQL Server
conexion = pyodbc.connect(
    'DRIVER={ODBC Driver 17 for SQL Server};'
    'SERVER=MENDOZA;'
    'DATABASE=EXAMEN;'
    'Trusted_Connection=yes;'
)

# 🔹 Ruta raíz: redirige al login
@app.route("/")
def inicio():
    return redirect(url_for("login"))

# 🔹 Ruta de login
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
            return redirect(url_for("panel"))
        else:
            return render_template("login.html", error="Usuario o contraseña incorrecta")

    return render_template("login.html")

# 🔹 Ruta de registro
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        apellido = request.form["apellido"]
        usuario = request.form["usuario"]
        correo = request.form["correo"]
        password = request.form["password"]
        rol = request.form["rol"]

        # Generar hash seguro
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        cursor = conexion.cursor()
        cursor.execute("""
            INSERT INTO usuarios (nombre, apellido, usuario, correo, password_hash, rol)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (nombre, apellido, usuario, correo, password_hash, rol))
        conexion.commit()

        return render_template("registro.html", mensaje="Usuario registrado correctamente")

    return render_template("registro.html")

# 🔹 Ruta del panel principal

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
            # Si el rol no está definido, vuelve al login
            return redirect(url_for("login"))
    else:
        return redirect(url_for("login"))


# 🔹 Ruta para cerrar sesión
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
