from flask import Flask  # Esta línea es necesaria para crear la app Flask
from dotenv import load_dotenv
import os

def create_app():
    load_dotenv()  # Asegúrate de cargar el archivo .env

    app = Flask(__name__)
    app.secret_key = 'test'  # Cambia esto por algo más seguro

    # Verifica si las variables están siendo cargadas
    print("MAILJET_API_KEY:", os.getenv("MAILJET_API_KEY"))
    print("MAILJET_API_SECRET:", os.getenv("MAILJET_API_SECRET"))

    # Importa y registra el Blueprint después de crear la app
    from app.routes import main_blueprint
    app.register_blueprint(main_blueprint)

    return app
