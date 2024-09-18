import bcrypt  # Asegúrate de instalar bcrypt
from flask import render_template, redirect, url_for, session, request, flash, Blueprint
import psycopg2
from dotenv import load_dotenv
import os

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

# Flask Blueprint
main_blueprint = Blueprint('main', __name__)

@main_blueprint.route('/')
def home():
    return redirect(url_for('main.login'))

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

                if is_admin:  # Si es administrador
                    session['user_type'] = 'admin'
                else:
                    session['user_type'] = 'user'

                # Aquí agregamos un print para verificar los valores
                print(f"Usuario logueado: {session['user']}, es admin: {session['is_admin']}")
                
                return redirect(url_for('main.inventory'))
            else:
                flash('Contraseña incorrecta. Por favor intenta de nuevo.')
        else:
            flash('Usuario no encontrado. Por favor intenta de nuevo.')

        return redirect(url_for('main.login'))
    
    return render_template('login.html')

@main_blueprint.route('/inventory')
def inventory():
    if 'user' not in session:
        return redirect(url_for('main.login'))

    user_email = session['user']
    is_admin = session.get('is_admin', False)

    database_api.conectar()

    if is_admin:
        # Obtener todos los ítems de todos los usuarios
        query = "SELECT * FROM items"
        database_api.db.execute(query)
        user_items = database_api.db.fetchall()
    else:
        # Obtener solo los ítems del usuario logueado
        query = "SELECT * FROM items WHERE user_email = %s"
        database_api.db.execute(query, (user_email,))
        user_items = database_api.db.fetchall()

    database_api.desconectar()

    return render_template('inventory.html', items=user_items, is_admin=is_admin)

@main_blueprint.route('/view_profile/<int:user_id>')
def view_profile(user_id):
    if 'user_type' in session and session['is_admin']:
        database_api.conectar()

        # Obtener información del usuario
        query_user = "SELECT * FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user = database_api.db.fetchone()

        # Obtener ítems del usuario
        query_items = "SELECT * FROM items WHERE user_id = %s"
        database_api.db.execute(query_items, (user_id,))
        user_items = database_api.db.fetchall()

        database_api.desconectar()

        if user:
            return render_template('view_profile.html', user=user, items=user_items)
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
        query_user = "SELECT * FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user = database_api.db.fetchone()

        if user:
            if request.method == 'POST':
                # Insertar un nuevo ítem en la base de datos
                query_insert = """
                INSERT INTO items (user_id, name, color, size, status, purchase_price, sale_price, condition, date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                database_api.db.execute(query_insert, (
                    user_id,
                    request.form['name'],
                    request.form['color'],
                    request.form['size'],
                    request.form['status'],
                    request.form['purchase_price'],
                    request.form.get('sale_price', 'N/A'),
                    request.form['condition'],
                    request.form['date']
                ))
                database_api.desconectar()

                flash('Ítem creado con éxito.')
                return redirect(url_for('main.view_profile', user_id=user_id))
            
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
            if request.method == 'POST':
                # Actualizar los datos del ítem en la base de datos
                query_update = """
                UPDATE items
                SET name = %s, color = %s, size = %s, status = %s, purchase_price = %s, sale_price = %s, condition = %s, date = %s
                WHERE id = %s
                """
                database_api.db.execute(query_update, (
                    request.form['name'],
                    request.form['color'],
                    request.form['size'],
                    request.form['status'],
                    request.form['purchase_price'],
                    request.form.get('sale_price', 'N/A'),
                    request.form['condition'],
                    request.form['date'],
                    item_id
                ))
                database_api.desconectar()

                flash(f'Ítem {item_id} actualizado con éxito.')
                return redirect(url_for('main.inventory'))
            
            database_api.desconectar()
            return render_template('edit_item.html', item=item_to_edit)
        else:
            flash(f'Ítem {item_id} no encontrado.')
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

            flash(f'Ítem {item_id} eliminado con éxito.')
            return redirect(url_for('main.inventory'))
        else:
            flash(f'Ítem {item_id} no encontrado.')
            return redirect(url_for('main.inventory'))
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/payout')
def payout():
    if 'user_type' in session:
        if session['is_admin']:
            # Obtener todos los ítems con estado 'sold'
            database_api.conectar()
            query = "SELECT * FROM items WHERE status = 'sold'"
            database_api.db.execute(query)
            payout_items = database_api.db.fetchall()
            database_api.desconectar()
        else:
            # Obtener los ítems del usuario con estado 'sold'
            user_email = session['user']
            database_api.conectar()
            query = "SELECT * FROM items WHERE user_email = %s AND status = 'sold'"
            database_api.db.execute(query, (user_email,))
            payout_items = database_api.db.fetchall()
            database_api.desconectar()

        return render_template('payout.html', items=payout_items)
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/payout_history')
def payout_history():
    if 'user_type' in session:
        if session['is_admin']:
            # Obtener todos los ítems con estado 'paid' (historial de payout)
            database_api.conectar()
            query = "SELECT * FROM items WHERE status = 'paid'"
            database_api.db.execute(query)
            payout_history_items = database_api.db.fetchall()
            database_api.desconectar()
        else:
            # Obtener solo los ítems del usuario con estado 'paid'
            user_email = session['user']
            database_api.conectar()
            query = "SELECT * FROM items WHERE user_email = %s AND status = 'paid'"
            database_api.db.execute(query, (user_email,))
            payout_history_items = database_api.db.fetchall()
            database_api.desconectar()

        return render_template('payout_history.html', items=payout_history_items)
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
        query = "SELECT * FROM users"
        database_api.db.execute(query)
        users = database_api.db.fetchall()
        database_api.desconectar()

        return render_template('profile_admin.html', users=users)
    else:
        return redirect(url_for('main.login'))

@main_blueprint.route('/profile_user')
def profile_user():
    if 'user_type' in session and not session['is_admin']:
        user_email = session['user']
        database_api.conectar()

        query = "SELECT * FROM users WHERE email = %s"
        database_api.db.execute(query, (user_email,))
        user_profile = database_api.db.fetchone()

        database_api.desconectar()

        return render_template('profile_user.html', user=user_profile)
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

        query_user = "SELECT * FROM users WHERE id = %s"
        database_api.db.execute(query_user, (user_id,))
        user_to_edit = database_api.db.fetchone()

        if user_to_edit:
            if request.method == 'POST':
                # Actualizar los datos del usuario en la base de datos
                query_update = "UPDATE users SET email = %s, name = %s WHERE id = %s"
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
    return redirect(url_for('main.login'))
