import bcrypt  # Asegúrate de instalar bcrypt
from flask import render_template, redirect, url_for, session, request, flash, Blueprint
import psycopg2
from dotenv import load_dotenv
import os
from itsdangerous import URLSafeTimedSerializer
import smtplib  # o una librería de email más avanzada
from mailjet_rest import Client
import re
from werkzeug.security import generate_password_hash
import csv
from datetime import datetime


load_dotenv()

class database():
    conexion = None
    db = None

    def conectar(self):
        self.conexion = psycopg2.connect(os.environ.get('psql'))
        self.db = self.conexion.cursor()

    def desconectar(self):
        self.conexion.commit()
        self.db.close()
        self.conexion.close()

database_api = database()

def send_email(subject, item_name, to_email):
    # Usar directamente las variables de entorno
    api_key = os.getenv("MAILJET_API_KEY")
    api_secret = os.getenv("MAILJET_API_SECRET")

    if not api_key or not api_secret:
        print("MAILJET_API_KEY o MAILJET_API_SECRET no encontrados.")
        return

    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    # Estilo inline para el email
    html_content = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                    color: #333;
                }}
                .container {{
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                }}
                h1 {{
                    color: #4CAF50;
                    text-align: center;
                }}
                p {{
                    font-size: 16px;
                    margin-bottom: 15px;
                }}
                .footer {{
                    text-align: center;
                    font-size: 14px;
                    color: #777;
                    margin-top: 20px;
                }}
                .footer a {{
                    color: #4CAF50;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>¡Felicidades!</h1>
                <p>Nos complace informarte que tu ítem <strong>{item_name}</strong> ha sido vendido. Solicita un turno para coordinar el pago.</p>
                <p>Gracias por confiar en nosotros.</p>
                <div class="footer">
                    <p>Atira Consignment - Todos los derechos reservados.</p>
                </div>
            </div>
        </body>
    </html>
    """

    data = {
        'Messages': [
            {
                "From": {
                    "Email": "airplugventas@gmail.com",
                    "Name": "Atira Consignment"
                },
                "To": [
                    {
                        "Email": to_email
                    }
                ],
                "Subject": subject,
                "HTMLPart": html_content
            }
        ]
    }

    result = mailjet.send.create(data=data)
    if result.status_code == 200:
        print("Email sent successfully!")
    else:
        print(f"Error sending email: {result.status_code}, {result.text}")

# Función para enviar correo de restablecimiento de contraseña
def send_reset_email(to_email, token):
    reset_url = url_for('main.reset_password', token=token, _external=True)
    subject = "Restablecer tu contraseña"
    html_content = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                    color: #333;
                }}
                .container {{
                    width: 100%;
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 8px;
                }}
                h1 {{
                    color: #4CAF50;
                    text-align: center;
                }}
                p {{
                    font-size: 16px;
                    margin-bottom: 15px;
                }}
                .footer {{
                    text-align: center;
                    font-size: 14px;
                    color: #777;
                    margin-top: 20px;
                }}
                .footer a {{
                    color: #4CAF50;
                    text-decoration: none;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>¡Has solicitado restablecer tu contraseña!</h1>
                <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
                <p><a href="{reset_url}">Restablecer mi contraseña</a></p>
                <p>Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
                <div class="footer">
                    <p>Atira Consignment - Todos los derechos reservados.</p>
                </div>
            </div>
        </body>
    </html>
    """

    data = {
        'Messages': [
            {
                "From": {
                    "Email": "airplugventas@gmail.com",
                    "Name": "Atira Consignment"
                },
                "To": [
                    {
                        "Email": to_email
                    }
                ],
                "Subject": subject,
                "HTMLPart": html_content
            }
        ]
    }

    mailjet = Client(auth=(os.getenv("MAILJET_API_KEY"), os.getenv("MAILJET_API_SECRET")), version='v3.1')
    result = mailjet.send.create(data=data)

    if result.status_code == 200:
        print("Reset email sent successfully!")
    else:
        print(f"Error sending reset email: {result.status_code}, {result.text}")




# Flask Blueprint
main_blueprint = Blueprint('main', __name__)

@main_blueprint.route('/')
def home():
    return render_template('home.html')

@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Conectar a la base de datos
        database_api.conectar()
        
        # Consultar si el usuario existe en la base de datos
        query = "SELECT email, password, id, is_admin FROM users WHERE email = %s"
        database_api.db.execute(query, (email,))
        user = database_api.db.fetchone()  # Devuelve una tupla (email, password_hash, id, is_admin)
        
        database_api.desconectar()

        if user:
            db_email, db_password, user_id, is_admin = user

            # Compara la contraseña ingresada con la contraseña almacenada usando bcrypt
            if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
                session['user'] = db_email
                session['user_id'] = user_id
                session['is_admin'] = is_admin

                if is_admin:
                    session['user_type'] = 'admin'
                else:
                    session['user_type'] = 'user'
                
                return redirect(url_for('main.inventory'))  # Redirige a la página de inventario u otra página relevante
            else:
                flash('Email or password was incorrect', 'error')
        else:
            flash('Email or password was incorrect', 'error')

    # Si no es un POST o si hay un error en el login, se redirige a la misma página (home)
    return render_template('home.html')

@main_blueprint.route('/inventory', methods=['GET', 'POST'])
def inventory():
    if 'user' not in session:
        return redirect(url_for('main.login'))

    user_email = session['user']
    is_admin = session.get('is_admin', False)

    database_api.conectar()

    search_query = ""
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()

    if is_admin:
        query = "SELECT * FROM items WHERE name ILIKE %s AND status NOT IN ('sold', 'paid')"
        database_api.db.execute(query, ('%' + search_query + '%',))
        user_items = database_api.db.fetchall()
    else:
        query = "SELECT * FROM items WHERE user_email = %s AND status NOT IN ('sold', 'paid')"
        database_api.db.execute(query, (user_email,))
        user_items = database_api.db.fetchall()

    # Convertimos las tuplas en diccionarios para un manejo más sencillo en el template
    items_dict = []
    for item in user_items:
        item_dict = {
            'id': item[0],
            'name': item[2],
            'color': item[3],
            'size': item[4],
            'status': item[5],
            'net': item[6],
            'price': item[7],
            'condition': item[8],
            'date': item[9],
            'consignor': item[1]
        }
        items_dict.append(item_dict)

    database_api.desconectar()

    return render_template('inventory.html', items=items_dict, is_admin=is_admin)

@main_blueprint.route('/view_profile/<int:user_id>')
def view_profile(user_id):
    if 'user_type' in session and session['is_admin']:
        database_api.conectar()

        # Obtener información del usuario
        query_user = "SELECT id, email, name FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user_data = database_api.db.fetchone()

        # Obtener ítems del usuario
        query_items = "SELECT * FROM items WHERE user_id = %s"
        database_api.db.execute(query_items, (user_id,))
        user_items = database_api.db.fetchall()

        database_api.desconectar()

        if user_data:
            # Descomponer la tupla en un diccionario para mostrar en el template
            user = {
                'id': user_data[0],
                'email': user_data[1],
                'name': user_data[2]
            }

            # Convertimos los ítems en diccionarios
            items_dict = []
            for item in user_items:
                item_dict = {
                    'id': item[0],  # Ajusta los índices según tu tabla
                    'name': item[2],
                    'color': item[3],
                    'size': item[4],
                    'status': item[5],
                    'net': item[6],  # Cambiado a 'net'
                    'price': item[7],  # Cambiado a 'price'
                    'condition': item[8],
                    'date': item[9]
                }
                items_dict.append(item_dict)

            return render_template('view_profile.html', user=user, items=items_dict)
        else:
            flash('Usuario no encontrado.')
            return redirect(url_for('main.profile_admin'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/create_item/<int:user_id>', methods=['GET', 'POST'])
def create_item(user_id):
    if 'user_type' in session and session['user_type'] == 'admin':
        database_api.conectar()

        # Obtener información del usuario
        query_user = "SELECT id, email, name FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user_data = database_api.db.fetchone()

        if user_data:
            # Convertir la tupla en un diccionario
            user = {
                'id': user_data[0],
                'email': user_data[1],
                'name': user_data[2]
            }

            if request.method == 'POST':
                # Recoge los datos del formulario
                name = request.form.get('name')
                details = request.form.get('details')
                status = request.form.get('status')
                net = request.form.get('net')  # Cambiado a 'net'
                price = request.form.get('price')  # Cambiado a 'price'
                condition = request.form.get('condition')  # Cambiado a 'condition'

                # Validar que todos los campos obligatorios estén completos
                missing_fields = []
                if not name:
                    missing_fields.append("Nombre")
                if not net:
                    missing_fields.append("Net")
                if not status:
                    missing_fields.append("Estado")
                if not condition:
                    missing_fields.append("Condición")
                if not details:
                    missing_fields.append("Detalles")

                if missing_fields:
                    flash(f"Por favor completa los siguientes campos: {', '.join(missing_fields)}.", "error")
                    return redirect(url_for('main.create_item', user_id=user_id))

                # Insertar un nuevo ítem en la base de datos (AJUSTAR el orden de los campos)
                try:
                    query_insert = """
                    INSERT INTO items (user_id, name, details, status, net, price, condition, user_email)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    database_api.db.execute(query_insert, (
                        user_id, name, details, status, net, price, condition, user['email']
                    ))
                    database_api.desconectar()

                    flash('Ítem creado con éxito.')
                    return redirect(url_for('main.view_profile', user_id=user_id))
                except Exception as e:
                    database_api.desconectar()
                    flash(f'Error al crear el ítem: {str(e)}')
                    return redirect(url_for('main.create_item', user_id=user_id))

            database_api.desconectar()
            return render_template('create_item.html', user=user)
        else:
            flash('Usuario no encontrado.')
            return redirect(url_for('main.inventory'))
    else:
        return redirect(url_for('main.login'))



@main_blueprint.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
def edit_item(item_id):
    if 'user_type' in session and session['user_type'] == 'admin':
        database_api.conectar()

        # Obtener el ítem a editar
        query_item = "SELECT * FROM items WHERE id = %s"
        database_api.db.execute(query_item, (item_id,))
        item_to_edit = database_api.db.fetchone()

        if item_to_edit:
            # Convertimos la tupla en un diccionario
            item = {
                'id': item_to_edit[0],
                'name': item_to_edit[2],  # Nombre del ítem
                'details': item_to_edit[3],  # Detalles del ítem
                'status': item_to_edit[4],
                'net': item_to_edit[5],
                'price': item_to_edit[6],
                'condition': item_to_edit[7],
                'user_email': item_to_edit[8]  # El email del consignador
            }

            if request.method == 'POST':
                try:
                    print("Datos del formulario recibidos:", request.form)

                    # Conversión explícita de precios a float
                    try:
                        purchase_price = float(request.form['purchase_price'])
                        sale_price = float(request.form['sale_price']) if request.form['sale_price'] else None
                    except ValueError as e:
                        flash('Formato inválido en el campo de precios')
                        return redirect(url_for('main.edit_item', item_id=item_id))

                    # Actualizar los datos del ítem en la base de datos
                    query_update = """
                    UPDATE items
                    SET name = %s, details = %s, status = %s, net = %s, price = %s, condition = %s
                    WHERE id = %s
                    """
                    database_api.db.execute(query_update, (
                        request.form['name'],
                        request.form['details'],
                        request.form['status'],
                        purchase_price,
                        sale_price,
                        request.form['condition'],
                        item_id
                    ))

                    database_api.desconectar()
                    flash("Ítem actualizado con éxito.")
                    return redirect(url_for('main.inventory'))

                except Exception as e:
                    database_api.desconectar()
                    flash(f"Error al actualizar el ítem. Por favor, inténtalo más tarde. Error: {str(e)}")
                    return redirect(url_for('main.edit_item', item_id=item_id))

            return render_template('edit_item.html', item=item)

        else:
            flash('El ítem no existe o ha sido eliminado.')
            return redirect(url_for('main.inventory'))
    else:
        return redirect(url_for('main.login'))




@main_blueprint.route('/delete_item/<int:item_id>')
def delete_item(item_id):
    if 'user_type' in session and session['user_type'] == 'admin':
        database_api.conectar()

        # Obtener el ítem a eliminar
        query_item = "SELECT * FROM items WHERE id = %s"
        database_api.db.execute(query_item, (item_id,))
        item_to_delete = database_api.db.fetchone()

        if item_to_delete:
            # Eliminar el ítem
            query_delete = "DELETE FROM items WHERE id = %s"
            database_api.db.execute(query_delete, (item_id,))
            database_api.desconectar()

            return redirect(url_for('main.inventory'))
        else:
            return redirect(url_for('main.inventory'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/payout')
def payout():
    if 'user_type' in session:
        database_api.conectar()

        if session['is_admin']:
            # Obtener todos los ítems con estado 'sold'
            query = "SELECT * FROM items WHERE status = 'sold'"
            database_api.db.execute(query)
            payout_items = database_api.db.fetchall()
        else:
            # Obtener solo los ítems del usuario logueado con estado 'sold'
            user_email = session['user']
            query = "SELECT * FROM items WHERE user_email = %s AND status = 'sold'"
            database_api.db.execute(query, (user_email,))
            payout_items = database_api.db.fetchall()

        # Convertimos las tuplas en diccionarios para facilitar el acceso en el template
        items_dict = []
        for item in payout_items:
            item_dict = {
                'id': item[0],  
                'name': item[2],
                'color': item[3],
                'size': item[4],
                'status': item[5],
                'net': item[6],  # Asegúrate de que este campo es 'net'
                'price': item[7],  # Asegúrate de que este campo es 'price'
                'condition': item[8],
                'date': item[9],
                'consignor': item[1]  # Asegúrate de que este campo es 'consignor'
            }
            items_dict.append(item_dict)

        database_api.desconectar()

        # Pasamos la variable 'is_admin' a la plantilla
        return render_template('payout.html', items=items_dict, is_admin=session.get('is_admin', False))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/payout_history')
def payout_history():
    if 'user_type' in session:
        # Comprobamos si el usuario es admin
        is_admin = session.get('is_admin', False)
        
        if is_admin:
            # Obtener todos los ítems con estado 'paid'
            database_api.conectar()
            query = "SELECT * FROM items WHERE status = 'paid'"
            database_api.db.execute(query)
            payout_history_items = database_api.db.fetchall()
            database_api.desconectar()
        else:
            # Obtener solo los ítems del usuario logueado con estado 'paid'
            user_email = session['user']
            database_api.conectar()
            query = "SELECT * FROM items WHERE user_email = %s AND status = 'paid'"
            database_api.db.execute(query, (user_email,))
            payout_history_items = database_api.db.fetchall()
            database_api.desconectar()

        # Convertir las tuplas en diccionarios
        items_dict = []
        for item in payout_history_items:
            item_dict = {
                'id': item[0],  # Ajusta los índices según la estructura de tu tabla
                'name': item[2],
                'color': item[3],
                'size': item[4],
                'status': item[5],
                'net': item[6],
                'price': item[7],
                'condition': item[8],
                'consignor': item[1],
                'date': item[9]
            }
            items_dict.append(item_dict)

        # Pasamos `is_admin` a la plantilla para que se pueda usar en el HTML
        return render_template('payout_history.html', items=items_dict, is_admin=is_admin)
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/profile')
def profile():
    if 'user_type' in session:
        if session['is_admin']:
            return redirect(url_for('main.profile_admin'))
        else:
            return redirect(url_for('main.profile_user'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/profile_admin')
def profile_admin():
    if 'user_type' in session and session['is_admin']:
        database_api.conectar()

        # Obtenemos los usuarios como tuplas
        query = "SELECT id, email, name FROM users"
        database_api.db.execute(query)
        user_tuples = database_api.db.fetchall()

        # Convertimos las tuplas en diccionarios para facilitar el acceso en el template
        users = [{'id': user[0], 'email': user[1], 'name': user[2]} for user in user_tuples]

        database_api.desconectar()

        return render_template('profile_admin.html', users=users)
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/profile_user')
def profile_user():
    if 'user_type' in session and session['user_type'] == 'user':
        user_email = session['user']  # Obtiene el email del usuario de la sesión
        database_api.conectar()

        # Obtener información del usuario basado en el email
        query = "SELECT id, email, name FROM users WHERE email = %s"
        database_api.db.execute(query, (user_email,))
        user_profile = database_api.db.fetchone()

        database_api.desconectar()

        if user_profile:  # Verifica que se haya encontrado el usuario
            # Descomponer la tupla en un diccionario
            user = {
                'id': user_profile[0],
                'email': user_profile[1],
                'name': user_profile[2]
            }
            return render_template('profile_user.html', user=user)
        else:
            flash('Usuario no encontrado.')
            return redirect(url_for('main.login'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/create_user', methods=['GET', 'POST'])
def create_user():
    if 'user_type' in session and session['is_admin']:
        if request.method == 'POST':
            database_api.conectar()

            # Insertar el nuevo usuario en la base de datos
            query_insert = """
            INSERT INTO users (email, name, password, is_admin)
            VALUES (%s, %s, %s, %s)
            """
            password_hash = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            database_api.db.execute(query_insert, (
                request.form['email'],
                request.form['name'],
                password_hash.decode('utf-8'),
                request.form['role'] == 'admin'
            ))
            database_api.desconectar()

            flash('Usuario creado con éxito.')
            return redirect(url_for('main.profile_admin'))
        return render_template('create_user.html')
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_type' in session and session['is_admin']:
        database_api.conectar()

        # Obtener el usuario a editar
        query_user = "SELECT id, email, name FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user_data = database_api.db.fetchone()

        if user_data:
            # Descomponer la tupla en un diccionario
            user_to_edit = {
                'id': user_data[0],
                'email': user_data[1],
                'name': user_data[2]
            }

            if request.method == 'POST':
                # Actualizar los datos del usuario en la base de datos
                query_update = """
                UPDATE users
                SET email = %s, name = %s
                WHERE id = %s
                """
                database_api.db.execute(query_update, (
                    request.form['email'],
                    request.form['name'],
                    user_id
                ))
                database_api.desconectar()

                flash(f'Usuario {user_id} actualizado con éxito.')
                return redirect(url_for('main.profile_admin'))

            database_api.desconectar()
            return render_template('edit_user.html', user=user_to_edit)
        else:
            flash(f'Usuario {user_id} no encontrado.')
            return redirect(url_for('main.profile_admin'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    if 'user_type' in session and session['is_admin']:
        database_api.conectar()

        query_user = "SELECT * FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user_to_delete = database_api.db.fetchone()

        if user_to_delete:
            query_delete = "DELETE FROM users WHERE id = %s"
            database_api.db.execute(query_delete, (user_id,))
            database_api.desconectar()

            flash(f'Usuario {user_id} eliminado con éxito.')
            return redirect(url_for('main.profile_admin'))
        else:
            flash(f'Usuario {user_id} no encontrado.')
            return redirect(url_for('main.profile_admin'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.home'))

@main_blueprint.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_type' in session and session['user_type'] == 'user':
        user_email = session['user']
        database_api.conectar()

        # Actualizar los datos del usuario
        query_update = """
        UPDATE users
        SET email = %s, name = %s
        WHERE email = %s
        """
        database_api.db.execute(query_update, (
            request.form['email'],
            request.form['name'],
            user_email
        ))
        database_api.desconectar()

        flash('Perfil actualizado con éxito.')
        return redirect(url_for('main.profile_user'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        user_id = session['user_id']

        # Conectar a la base de datos
        database_api.conectar()

        # Obtener la contraseña actual del usuario
        query = "SELECT password FROM users WHERE id = %s"
        database_api.db.execute(query, (user_id,))
        user_data = database_api.db.fetchone()

        if not user_data:
            flash('Usuario no encontrado.')
            return redirect(url_for('main.profile_user'))

        db_password = user_data[0]

        # Verificar la contraseña actual
        if not bcrypt.checkpw(current_password.encode('utf-8'), db_password.encode('utf-8')):
            flash('La contraseña actual no es correcta.')
            return redirect(url_for('main.change_password'))

        # Verificar que la nueva contraseña y la confirmación coincidan
        if new_password != confirm_password:
            flash('Las contraseñas nuevas no coinciden.')
            return redirect(url_for('main.change_password'))

        # Encriptar la nueva contraseña y actualizarla
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Actualizar la contraseña en la base de datos
        update_query = "UPDATE users SET password = %s WHERE id = %s"
        database_api.db.execute(update_query, (new_password_hash, user_id))
        database_api.desconectar()

        flash('Contraseña actualizada correctamente.')
        return redirect(url_for('main.profile_user'))
    
    return render_template('change_password.html')


# Modificación en la ruta /forgot_password para separar el correo de restablecimiento
@main_blueprint.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # Verificar si el email existe en la base de datos
        database_api.conectar()
        query = "SELECT id, email FROM users WHERE email = %s"
        database_api.db.execute(query, (email,))
        user = database_api.db.fetchone()

        if user:
            # Generar el token para restablecer la contraseña
            s = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))
            token = s.dumps(email, salt=os.getenv("SECURITY_PASSWORD_SALT"))

            # Enviar el correo con el enlace de restablecimiento
            send_reset_email(email, token)

            flash("Te hemos enviado un correo con el enlace para restablecer tu contraseña.", "success")
        else:
            flash("Este correo no está registrado.", "error")

        database_api.desconectar()
        return redirect(url_for('main.home'))

    return render_template('forgot_password.html')

@main_blueprint.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        s = URLSafeTimedSerializer(os.getenv("SECRET_KEY"))
        email = s.loads(token, salt=os.getenv("SECURITY_PASSWORD_SALT"), max_age=3600)  # El token es válido por 1 hora

        if request.method == 'POST':
            new_password = request.form['password']
            
            # Verificar que la contraseña sea válida (por ejemplo, longitud mínima)
            if len(new_password) < 6:
                flash('La contraseña debe tener al menos 6 caracteres', 'error')
                return render_template('reset_password.html', token=token)

            # Actualizar la contraseña en la base de datos
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            database_api.conectar()

            query = "UPDATE users SET password = %s WHERE email = %s"
            database_api.db.execute(query, (hashed_password, email))
            database_api.desconectar()

            flash('Tu contraseña ha sido actualizada con éxito.', 'success')
            return redirect(url_for('main.home'))

        return render_template('reset_password.html', token=token)
    except Exception as e:
        flash('El enlace de restablecimiento ha expirado o no es válido.', 'error')
        return redirect(url_for('main.home'))

@main_blueprint.route('/import_items/<int:user_id>', methods=['POST'])
def import_items(user_id):
    if 'user_type' in session and session['user_type'] == 'admin':
        file = request.files.get('file')
        
        if file and file.filename.endswith('.csv'):
            try:
                # Leer el archivo CSV
                csv_data = csv.reader(file.stream)
                next(csv_data)  # Saltar el encabezado si lo tiene

                # Procesar cada fila del CSV
                for row in csv_data:
                    # Asegurarse de que la fila tiene los datos necesarios
                    if len(row) >= 4:
                        name = row[0]
                        details = row[1]
                        price = float(row[2])
                        net = float(row[3])
                        status = 'in stock'
                        date = datetime.now().strftime('%Y-%m-%d')

                        # Insertar los datos en la base de datos
                        query = """
                        INSERT INTO items (user_id, name, details, price, net, status, date)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """
                        database_api.conectar()
                        database_api.db.execute(query, (user_id, name, details, price, net, status, date))
                        database_api.desconectar()
                
                flash("Archivo cargado correctamente y los ítems han sido importados.", "success")
                return redirect(url_for('main.view_profile', user_id=user_id))

            except Exception as e:
                flash(f"Hubo un error al importar los ítems: {e}", "error")
                return redirect(url_for('main.view_profile', user_id=user_id))
        else:
            flash("Por favor, seleccione un archivo CSV válido.", "error")
            return redirect(url_for('main.view_profile', user_id=user_id))
    else:
        return redirect(url_for('main.login'))



# Función para manejar la venta de un ítem y su cambio de estado a "SOLD"
@main_blueprint.route('/complete_sale', methods=['POST'])
def complete_sale():
    try:
        item_id = request.form['item_id']
        payment_amount = float(request.form['payment_amount'])  # Monto pagado
        due_amount = float(request.form['due_amount'])  # Monto pendiente

        # Verifica si el pago cubre el monto total (DUE debe ser 0)
        if payment_amount < due_amount:
            flash("El monto pagado es insuficiente. El pago no es completo.")
            return redirect(url_for('main.pos'))  # O a la página del POS

        # Actualiza el estado del ítem a "SOLD"
        query_update = """
        UPDATE items
        SET status = 'sold'
        WHERE id = %s
        """
        database_api.conectar()
        database_api.db.execute(query_update, (item_id,))
        database_api.desconectar()

        # Si todo está bien, redirige al administrador a la vista de payout o el historial de ventas
        flash('Venta completada con éxito.')
        return redirect(url_for('main.payout'))

    except Exception as e:
        database_api.desconectar()
        flash(f'Error al completar la venta: {str(e)}')
        return redirect(url_for('main.pos'))


# Función para generar el recibo
@main_blueprint.route('/generate_receipt', methods=['POST'])
def generate_receipt():
    try:
        # Obtener los detalles de la venta (monto pagado, ítems, etc.)
        sale_id = request.form['sale_id']
        items = get_items_for_sale(sale_id)  # Aquí deberías obtener los ítems relacionados con esta venta
        total_amount = request.form['total_amount']  # Total de la venta
        payment_method = request.form['payment_method']  # Efectivo, tarjeta, etc.

        # Generar el recibo como PDF o mostrarlo en pantalla
        generate_pdf_receipt(items, total_amount, payment_method, sale_id)

        # Redirige a la página de confirmación o la vista de ventas
        flash('Recibo generado correctamente.')
        return redirect(url_for('main.pos'))

    except Exception as e:
        flash(f'Error al generar el recibo: {str(e)}')
        return redirect(url_for('main.pos'))
    
@main_blueprint.route('/pos', methods=['GET', 'POST'])
def pos():
    if 'user_type' in session and session['user_type'] == 'admin':
        # Obtener todos los ítems disponibles
        database_api.conectar()
        query = "SELECT * FROM items WHERE status != 'sold'"
        database_api.db.execute(query)
        items = database_api.db.fetchall()
        database_api.desconectar()

        if request.method == 'POST':
            item_id = request.form.get('item_id')  # El ID del ítem seleccionado
            payment_amount = float(request.form.get('payment_amount'))
            payment_method = request.form.get('payment_method')

            # Actualizar el estado del ítem a 'sold'
            database_api.conectar()
            query_update = "UPDATE items SET status = 'sold' WHERE id = %s"
            database_api.db.execute(query_update, (item_id,))
            database_api.desconectar()

            # Aquí debes añadir la lógica para el pago y calcular el monto restante

            return redirect(url_for('main.pos'))

        return render_template('pos.html', items=items)
    else:
        return redirect(url_for('main.login'))



# Manejo de errores de actualización de ítem
@main_blueprint.route('/update_item_status', methods=['POST'])
def update_item_status():
    try:
        item_id = request.form['item_id']
        new_status = request.form['status']
        
        # Actualiza el estado del ítem
        query_update = """
        UPDATE items
        SET status = %s
        WHERE id = %s
        """
        database_api.conectar()
        database_api.db.execute(query_update, (new_status, item_id))
        database_api.desconectar()

        flash('Estado actualizado correctamente.')
        return redirect(url_for('main.inventory'))
    except Exception as e:
        database_api.desconectar()
        flash(f'Error al actualizar el ítem: {str(e)}')
        return redirect(url_for('main.inventory'))
