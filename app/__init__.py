from flask import Flask

def create_app():
    app = Flask(__name__)
    app.secret_key = 'test'  # Cambia esto por algo más seguro

    # Importa y registra el Blueprint después de crear la app
    from app.routes import main_blueprint
    app.register_blueprint(main_blueprint)

    return app
