from flask import Flask, render_template, request
from verifier import verificador

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = ""
    if request.method == "POST":
        correo = request.form["correo"]
        resultado = verificador.detectar_fraude(correo)
    return render_template("index.html", resultado=resultado)

if __name__ == "__main__":
    app.run(debug=True)
