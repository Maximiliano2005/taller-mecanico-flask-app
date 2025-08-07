from flask import Flask, render_template, render_template_string, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import datetime, timedelta # Importa datetime para usarlo en los modelos
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user # Para la gestión de sesión de usuario
import pytz
import locale 
from functools import wraps # ¡Importa wraps para el decorador de roles!
from dotenv import load_dotenv
from flask_migrate import Migrate
import click

load_dotenv() # Carga las variables de entorno del archivo .env


# Inicializa la aplicación Flask
app = Flask(__name__)


@app.cli.command("crear-admin")
@click.argument("password")
def crear_admin(password):
    """Crea un usuario administrador inicial.
    
    Uso: flask crear-admin 'tu-contrasena-segura'
    """
    # 1. Verifica si un usuario admin ya existe
    admin_user = User.query.filter_by(username='admin').first()

    if admin_user:
        click.echo("El usuario 'admin' ya existe en la base de datos.")
    else:
        try:
            # 2. Crea el nuevo usuario sin la contraseña encriptada
            new_admin = User(
                username='admin',
                role='admin' # Asigna el rol 'admin'
            )
            
            # 3. Usa el método set_password del modelo para encriptar y asignar la contraseña
            #    NOTA: ¡Asegúrate de que este método exista en tu modelo User!
            new_admin.set_password(password)

            # 4. Agrega el usuario a la sesión y guarda en la base de datos
            db.session.add(new_admin)
            db.session.commit()
            
            click.echo(f"Usuario 'admin' creado exitosamente.")
            click.echo("Puedes iniciar sesión con el nombre de usuario 'admin'.")

        except Exception as e:
            db.session.rollback()
            click.echo(f"Ocurrió un error al crear el usuario: {e}", err=True)

# --- Configuración de la Base de Datos ---

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'holaviejoediondo210423') 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 
    'postgresql://[postgres]:[vLhuZVtWMdwESYBAogFcXRhJJvjczUVz]@trolley.proxy.rlwy.net:42012/[taller.db]')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 


db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' 

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False) # Almacenará el hash de la contraseña
    role = db.Column(db.String(50), default='mecanico', nullable=False) # 'admin', 'cajero', 'mecanico'

    def set_password(self, password):
        # Almacena el hash de la contraseña en la columna 'password'
        self.password = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        # Verifica la contraseña ingresada con el hash almacenado en la columna 'password'
        return check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

@login_manager.user_loader
def load_user(user_id):
    # Ahora 'User' está definido cuando se llama esta función
    return db.session.get(User, int(user_id))

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Debes iniciar sesión para acceder a esta página.', 'warning')
                return redirect(url_for('login'))

            # --- ¡AÑADE ESTA LÍNEA TEMPORALMENTE PARA DEPURAR! ---
            print(f"DEBUG ROLE CHECK: User: {current_user.username}, Role: '{current_user.role}', Allowed: {allowed_roles}")
            # --- FIN DEPURACIÓN ---

            if current_user.role not in allowed_roles:
                flash(f'No tienes permiso ({current_user.role.capitalize()}) para acceder a esta página.', 'danger')
                return redirect(url_for('index')) # O a una página de "Acceso Denegado"
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- Configuración de localización para formato de moneda (FILTRO CLP) ---
# Intentaremos varias opciones para la localización de Chile.
# Es crucial que una de estas funcione para que locale.format_string opere correctamente.
locales_chile = ['es_CL.UTF-8', 'es_CL', 'Spanish_Chile.1252', 'es_CL.cp1252']
locale_configurado = False
for loc in locales_chile:
    try:
        locale.setlocale(locale.LC_ALL, loc)
        locale_configurado = True
        break
    except locale.Error:
        continue

if not locale_configurado:
    print("Advertencia: No se pudo configurar ninguna localización para Chile. El formato de moneda usará un método alternativo para separadores de miles.")


def format_clp(value):
    """
    Formatea un número como moneda chilena sin decimales, con separador de miles.
    Retorna una cadena vacía si el valor es None o no es numérico.
    """
    if value is None:
        return ""

    try:
        numeric_value = int(float(value))
    except (ValueError, TypeError):
        print(f"Advertencia: El valor '{value}' no es un número válido para formatear en CLP. Retornando vacío.")
        return ""

    formatted_str = f"{numeric_value:,}"

    return formatted_str.replace(",", ".")


# Registramos el filtro 'clp' en el entorno de Jinja2
app.jinja_env.filters['clp'] = format_clp

# --- Modelos de la Base de Datos ---
# Aquí definimos las tablas de nuestra base de datos como clases de Python.

# Tabla Repuestos
class Repuesto(db.Model):
    id_repuesto = db.Column(db.Integer, primary_key=True)
    nombre_repuesto = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    marca_repuesto = db.Column(db.String(50), nullable=True)
    precio_compra = db.Column(db.Float, nullable=False)
    precio_venta = db.Column(db.Float, nullable=False)
    stock_actual = db.Column(db.Integer, nullable=False)
    stock_minimo = db.Column(db.Integer, nullable=False, default=10)
    ubicacion_fisica = db.Column(db.String(100), nullable=True)
    modelos_compatibles = db.Column(db.Text, nullable=True) # Sin validación

    def __repr__(self):
        return f'<Repuesto {self.nombre_repuesto}>'

# Tabla Clientes
class Cliente(db.Model):
    id_cliente = db.Column(db.Integer, primary_key=True)
    nombre_completo = db.Column(db.String(100), nullable=False)
    celular = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), nullable=True)
    # Relación: Un cliente puede tener muchos vehículos
    vehiculos = db.relationship('Vehiculo', backref='cliente', lazy=True)

    def __repr__(self):
        return f'<Cliente {self.nombre_completo}>'

# Tabla Vehiculos
class Vehiculo(db.Model):
    id_vehiculo = db.Column(db.Integer, primary_key=True)
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=False)
    patente = db.Column(db.String(20), unique=True, nullable=False)
    marca = db.Column(db.String(50), nullable=False)
    modelo = db.Column(db.String(50), nullable=False)
    anio = db.Column(db.Integer, nullable=True)
    kilometraje = db.Column(db.Integer, nullable=True)
    notas_vehiculo = db.Column(db.Text, nullable=True)
    # Relación: Un vehículo puede tener muchas Órdenes de Trabajo
    ordenes_de_trabajo = db.relationship('OrdenTrabajo', back_populates='vehiculo', lazy=True)

    def __repr__(self):
        return f'<Vehiculo {self.patente}>'

# Tabla Ordenes_Trabajo (Definición ÚNICA y corregida)
class OrdenTrabajo(db.Model):
    id_ot = db.Column(db.Integer, primary_key=True)
    id_vehiculo = db.Column(db.Integer, db.ForeignKey('vehiculo.id_vehiculo'), nullable=False)
    fecha_ingreso = db.Column(db.DateTime, nullable=False, default=datetime.now)
    descripcion_trabajo = db.Column(db.Text, nullable=False)
    mecanico_asignado = db.Column(db.String(100), nullable=True)
    valor_mano_obra = db.Column(db.Float, nullable=False)
    fecha_entrega_real = db.Column(db.DateTime, nullable=True)
    valor_total_servicio = db.Column(db.Float, nullable=False, default=0.0)
    estado = db.Column(db.String(50), default='Pendiente', nullable=False) # <--- ¡AÑADE ESTA LÍNEA!

    detalles_ot = db.relationship('DetalleOT', backref='orden_trabajo', lazy=True, cascade="all, delete-orphan")
    vehiculo = db.relationship('Vehiculo', back_populates='ordenes_de_trabajo')

    def __repr__(self):
        return f'<OrdenTrabajo {self.id_ot} - {self.descripcion_trabajo}>'

# Tabla Detalle_OT (Repuestos usados en una OT) (Definición ÚNICA y corregida)
class DetalleOT(db.Model):
    id_detalle_ot = db.Column(db.Integer, primary_key=True)
    id_ot = db.Column(db.Integer, db.ForeignKey('orden_trabajo.id_ot'), nullable=False)
    id_repuesto = db.Column(db.Integer, db.ForeignKey('repuesto.id_repuesto'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    
    precio_unitario_al_momento = db.Column(db.Float, nullable=False) 

    
    repuesto = db.relationship('Repuesto', backref='detalles_ot_usados_en')

    def __repr__(self):
        return f'<DetalleOT OT:{self.id_ot} Rep:{self.id_repuesto} Cant:{self.cantidad}>'

# Tabla Ventas (para ventas directas de repuestos o cierre de servicios)
class Venta(db.Model):
    id_venta = db.Column(db.Integer, primary_key=True)
    fecha_venta = db.Column(db.DateTime, nullable=False, default=datetime.now)
    id_cliente = db.Column(db.Integer, db.ForeignKey('cliente.id_cliente'), nullable=True)
    total_venta = db.Column(db.Float, nullable=False)
    tipo_venta = db.Column(db.String(50), nullable=False)
    id_ot_asociada = db.Column(db.Integer, db.ForeignKey('orden_trabajo.id_ot'), nullable=True)
    saldo_pendiente = db.Column(db.Float, nullable=False, default=0.0)

    # Relación con Pagos
    pagos = db.relationship('Pago', backref='venta', lazy=True)
    # Relación con el cliente (opcional, si se necesita acceso directo a los datos del cliente desde la venta)
    cliente = db.relationship('Cliente', backref='ventas')

    detalles_venta = db.relationship('DetalleVenta', backref='venta', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Venta {self.id_venta} - {self.total_venta}>'

# Tabla Pagos
class Pago(db.Model):
    id_pago = db.Column(db.Integer, primary_key=True)
    id_venta = db.Column(db.Integer, db.ForeignKey('venta.id_venta'), nullable=False)
    monto = db.Column(db.Float, nullable=False)
    metodo_pago = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.String(255))
    fecha_pago = db.Column(db.DateTime, nullable=False, default=datetime.now) # ¡ESTA ES LA LÍNEA QUE FALTABA!

    def __repr__(self):
        return f'<Pago {self.id_pago} - Monto: {self.monto}>'
    
# Tabla DetalleVenta (Repuestos vendidos en una Venta Directa)
class DetalleVenta(db.Model):
    id_detalle_venta = db.Column(db.Integer, primary_key=True)
    id_venta = db.Column(db.Integer, db.ForeignKey('venta.id_venta'), nullable=False)
    id_repuesto = db.Column(db.Integer, db.ForeignKey('repuesto.id_repuesto'), nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    precio_venta_unitario_al_momento = db.Column(db.Float, nullable=False) # Precio del repuesto al momento de la venta

    # Relación con Repuesto
    repuesto = db.relationship('Repuesto', backref='detalles_venta_usados_en')

    def __repr__(self):
        return f'<DetalleVenta Venta:{self.id_venta} Rep:{self.id_repuesto} Cant:{self.cantidad}>'
    

# --- Rutas de la Aplicación (URLs) ---

# --- Rutas de Autenticación ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index')) 

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash(f'¡Bienvenido, {user.username.capitalize()} ({user.role.capitalize()})!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos.', 'danger')

    return render_template('login.html')

# Ruta de Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# --- Ruta para Cambiar Contraseña ---
@app.route('/change_password', methods=['GET', 'POST'])
@login_required # Solo usuarios logueados pueden cambiar su contraseña
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Validaciones básicas del formulario
        if not old_password or not new_password or not confirm_new_password:
            flash('Todos los campos son obligatorios.', 'danger')
            return render_template('change_password.html')

        if not current_user.check_password(old_password):
            flash('La contraseña actual es incorrecta.', 'danger')
            return render_template('change_password.html')

        if new_password != confirm_new_password:
            flash('Las nuevas contraseñas no coinciden.', 'danger')
            return render_template('change_password.html')

        if len(new_password) < 6: # Ejemplo: La nueva contraseña debe tener al menos 6 caracteres
            flash('La nueva contraseña debe tener al menos 6 caracteres.', 'danger')
            return render_template('change_password.html')

        # Actualiza la contraseña del usuario actual
        current_user.set_password(new_password)
        try:
            db.session.commit()
            flash('Contraseña actualizada exitosamente.', 'success')
            return redirect(url_for('index')) 
        except Exception as e:
            db.session.rollback()
            flash(f'Error al cambiar contraseña: {str(e)}', 'danger')
            print(f"Error changing password: {e}")

    # Si es un GET request, simplemente renderiza el formulario
    return render_template('change_password.html')

# --- Rutas para la Gestión de Usuarios (Admin) ---
# Esta es la ruta principal que lista todos los usuarios
@app.route('/admin/users')
@login_required
@role_required(['admin']) # Solo Admin puede listar usuarios
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

# Esta ruta es para editar un usuario específico
@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.role = request.form['role']
        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
        try:
            db.session.commit()
            flash('Usuario actualizado exitosamente.', 'success')
            return redirect(url_for('manage_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar usuario: {str(e)}', 'danger')
            print(f"Error editing user: {e}")
    
    available_roles = ['admin', 'cajero', 'mecanico']
    return render_template('edit_user.html', user=user, available_roles=available_roles)

# Esta ruta es para eliminar un usuario específico
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['admin'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('No puedes eliminar tu propia cuenta.', 'danger')
        return redirect(url_for('manage_users'))
    try:
        db.session.delete(user)
        db.session.commit()
        flash('Usuario eliminado exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar usuario: {str(e)}', 'danger')
        print(f"Error deleting user: {e}")
    return redirect(url_for('manage_users'))

# Ruta Index/Inicio
@app.route('/')
@app.route('/index') # Puedes tener ambas rutas
@login_required
def index():
    repuestos_bajo_stock = Repuesto.query.filter(Repuesto.stock_actual <= Repuesto.stock_minimo).all()
    total_ordenes_pendientes = OrdenTrabajo.query.filter_by(estado='Pendiente').count()
    
    # Calcular ventas de hoy usando la zona horaria de Chile
    chile_tz = pytz.timezone('America/Santiago')
    today_start = datetime.now(chile_tz).replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = datetime.now(chile_tz).replace(hour=23, minute=59, second=59, microsecond=999999)

    # Asegúrate de que las fechas de la BD también sean timezone-aware si las guardas así
    # O compara solo la parte de la fecha si no estás manejando TZ en la BD
    total_ventas_hoy = Venta.query.filter(Venta.fecha_venta >= today_start.astimezone(pytz.utc), 
                                        Venta.fecha_venta <= today_end.astimezone(pytz.utc)).count()

    return render_template('index.html',
                           repuestos_bajo_stock=repuestos_bajo_stock,
                           total_ordenes_pendientes=total_ordenes_pendientes,
                           total_ventas_hoy=total_ventas_hoy)

# --- Rutas de Gestión de Usuarios (Admin) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role', 'mecanico') # Captura el rol del formulario

        if not username or not password or not confirm_password:
            flash('Todos los campos son obligatorios.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Las contraseñas no coinciden.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('El nombre de usuario ya existe.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, role=role)
        new_user.set_password(password) # Usar el método seguro para guardar la contraseña

        try:
            db.session.add(new_user)
            db.session.commit()
            from flask_login import login_user
            login_user(new_user)  # Loguear automáticamente al usuario
            flash(f'Usuario {username} ({role.capitalize()}) registrado exitosamente!', 'success')
            return redirect(url_for('index')) # O a una página de gestión de usuarios
        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar usuario: {str(e)}', 'danger')
            print(f"Error al registrar usuario: {e}")
    
    # Pasa los roles disponibles a la plantilla para el dropdown
    available_roles = ['admin', 'cajero', 'mecanico']
    return render_template('register.html', available_roles=available_roles)

@app.route('/create_initial_admin')
def create_initial_admin():
    if not User.query.filter_by(username='admin').first():
        hashed_password = generate_password_hash('adminpass', method='pbkdf2:sha256') # ¡CAMBIA ESTA CONTRASEÑA POR UNA FUERTE!
        admin_user = User(username='admin', password=hashed_password, role='admin')
        db.session.add(admin_user)
        db.session.commit()
        return "Usuario Admin inicial 'admin' creado con contraseña 'adminpass'. ¡CAMBIA LA CONTRASEÑA DE INMEDIATO!"
    return "El usuario Admin inicial ya existe."

# --- Rutas para la Gestión de Repuestos (Inventario) ---

@app.route('/inventario')
@login_required 
@role_required(['admin', 'cajero'])
def listar_repuestos():
    repuestos = Repuesto.query.all() # Obtiene todos los repuestos de la BD
    return render_template('listar_repuestos.html', repuestos=repuestos)

@app.route('/inventario/agregar', methods=['GET', 'POST'])
@login_required 
@role_required(['admin', 'cajero'])
def agregar_repuesto():
    if request.method == 'POST':
        # Recoge los datos del formulario
        nombre_repuesto = request.form['nombre_repuesto']
        descripcion = request.form['descripcion']
        marca_repuesto = request.form['marca_repuesto']
        precio_compra = float(request.form['precio_compra'])
        precio_venta = float(request.form['precio_venta'])
        stock_actual = int(request.form['stock_actual'])
        stock_minimo = int(request.form['stock_minimo'])
        ubicacion_fisica = request.form['ubicacion_fisica']
        modelos_compatibles = request.form['modelos_compatibles']

        # Crea un nuevo objeto Repuesto
        nuevo_repuesto = Repuesto(
            nombre_repuesto=nombre_repuesto,
            descripcion=descripcion,
            marca_repuesto=marca_repuesto,
            precio_compra=precio_compra,
            precio_venta=precio_venta,
            stock_actual=stock_actual,
            stock_minimo=stock_minimo,
            ubicacion_fisica=ubicacion_fisica,
            modelos_compatibles=modelos_compatibles
        )

        try:
            db.session.add(nuevo_repuesto) # Agrega el repuesto a la sesión de la BD
            db.session.commit()          # Guarda los cambios en la BD
            flash('Repuesto agregado exitosamente!', 'success')
            return redirect(url_for('listar_repuestos')) # Redirige a la lista de repuestos
        except Exception as e:
            db.session.rollback() # Si hay un error, revierte la transacción
            flash(f'Error al agregar repuesto: {str(e)}', 'danger')
            print(f"Error: {e}") # Para depuración en la consola

    return render_template('formulario_repuesto.html') # Muestra el formulario si es método GET

# --- MODIFICACIÓN EN app.py para la ruta editar_repuesto ---
@app.route('/inventario/editar/<int:id_repuesto>', methods=['GET', 'POST']) # ¡Cambia 'id' por 'id_repuesto' aquí!
@login_required
@role_required(['admin', 'cajero'])
def editar_repuesto(id_repuesto): # ¡Y cambia el parámetro de la función de 'id' a 'id_repuesto' aquí!
    repuesto = Repuesto.query.get_or_404(id_repuesto) # Ahora usa el nuevo nombre del parámetro
    
    if request.method == 'POST':
        # Actualiza los datos del repuesto con los del formulario
        repuesto.nombre_repuesto = request.form['nombre_repuesto']
        repuesto.descripcion = request.form['descripcion']
        repuesto.marca_repuesto = request.form['marca_repuesto']
        repuesto.precio_compra = float(request.form['precio_compra'])
        repuesto.precio_venta = float(request.form['precio_venta'])
        repuesto.stock_actual = int(request.form['stock_actual'])
        repuesto.stock_minimo = int(request.form['stock_minimo'])
        repuesto.ubicacion_fisica = request.form['ubicacion_fisica']
        repuesto.modelos_compatibles = request.form['modelos_compatibles']

        try:
            db.session.commit() # Guarda los cambios en la BD
            flash('Repuesto actualizado exitosamente!', 'success')
            return redirect(url_for('listar_repuestos'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar repuesto: {str(e)}', 'danger')
            print(f"Error: {e}")

    return render_template('formulario_repuesto.html', repuesto=repuesto)

@app.route('/inventario/eliminar/<int:id>', methods=['POST'])
@login_required
@role_required(['admin'])
def eliminar_repuesto(id):
    repuesto = Repuesto.query.get_or_404(id)

    try:
        db.session.delete(repuesto) # Elimina el repuesto de la sesión
        db.session.commit()        # Guarda los cambios en la BD
        flash('Repuesto eliminado exitosamente!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar repuesto: {str(e)}', 'danger')
        print(f"Error: {e}")

    return redirect(url_for('listar_repuestos'))

# --- Rutas para la Gestión de Clientes y Vehículos ---

@app.route('/clientes')
@login_required 
def listar_clientes():
    # Obtiene todos los clientes y precarga sus vehículos para mostrarlos en la tabla
    clientes = Cliente.query.options(db.joinedload(Cliente.vehiculos)).all()
    return render_template('listar_clientes.html', clientes=clientes)

@app.route('/clientes/agregar', methods=['GET', 'POST'])
@login_required
def agregar_cliente():
    if request.method == 'POST':
        nombre_completo = request.form['nombre_completo']
        celular = request.form['celular']
        email = request.form.get('email')

        try:
            nuevo_cliente = Cliente(nombre_completo=nombre_completo, celular=celular, email=email)
            db.session.add(nuevo_cliente)
            db.session.commit()
            flash('Cliente agregado exitosamente!', 'success')
            return redirect(url_for('listar_clientes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al agregar cliente: {str(e)}', 'danger')
            print(f"Error al agregar cliente: {e}")

    return render_template('formulario_solo_cliente.html') # Usar el nuevo template

@app.route('/clientes/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_cliente(id):
    cliente = Cliente.query.get_or_404(id)

    if request.method == 'POST':
        cliente.nombre_completo = request.form['nombre_completo']
        cliente.celular = request.form['celular']
        cliente.email = request.form.get('email')

        try:
            db.session.commit()
            flash('Cliente actualizado exitosamente!', 'success')
            return redirect(url_for('listar_clientes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar cliente: {str(e)}', 'danger')
            print(f"Error: {e}")

    return render_template('formulario_solo_cliente.html', cliente=cliente) # Usar el nuevo template

@app.route('/clientes/eliminar/<int:id>', methods=['POST'])
@login_required
@role_required(['admin'])
def eliminar_cliente(id):
    cliente = Cliente.query.get_or_404(id)

    try:
        # Eliminar vehículos asociados primero (debido a la relación de clave foránea)
        for vehiculo in cliente.vehiculos:
            db.session.delete(vehiculo)
        db.session.delete(cliente)
        db.session.commit()
        flash('Cliente y vehículos asociados eliminados exitosamente!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar cliente: {str(e)}', 'danger')
        print(f"Error al eliminar cliente: {e}")

    return redirect(url_for('listar_clientes'))

# ... (Después de def editar_cliente(id_cliente):) ...

@app.route('/clientes/ver/<int:id_cliente>')
@login_required
def ver_cliente(id_cliente):
    cliente = Cliente.query.get_or_404(id_cliente)
    return render_template('ver_cliente.html', cliente=cliente)


@app.route('/clientes/<int:id_cliente>/vehiculos')
def administrar_vehiculos_cliente(id_cliente):
    cliente = Cliente.query.get_or_404(id_cliente)
    # Cargamos los vehículos del cliente
    return render_template('administrar_vehiculos.html', cliente=cliente)

@app.route('/clientes/<int:id_cliente>/vehiculos/agregar', methods=['GET', 'POST'])
def agregar_vehiculo(id_cliente):
    cliente_actual = Cliente.query.get_or_404(id_cliente)

    # Obtenemos todos los clientes disponibles para el dropdown en la plantilla
    clientes_disponibles = Cliente.query.all()

    if request.method == 'POST':
        patente = request.form['patente'].upper()
        marca_vehiculo = request.form['marca_vehiculo']
        modelo_vehiculo = request.form['modelo_vehiculo']
        anio_vehiculo = int(request.form['anio_vehiculo']) if request.form['anio_vehiculo'] else None
        kilometraje = int(request.form['kilometraje']) if request.form['kilometraje'] else None
        notas_vehiculo = request.form.get('notas_vehiculo')

        id_cliente_para_asociar = request.form.get('id_cliente', type=int)
        if not id_cliente_para_asociar:
            id_cliente_para_asociar = id_cliente # Fallback al id_cliente de la URL

        try:
            if Vehiculo.query.filter_by(patente=patente).first():
                flash(f'Ya existe un vehículo registrado con la patente: {patente}', 'danger')
                # Pasa los datos del formulario de vuelta y la lista de clientes disponibles
                return render_template('formulario_vehiculo.html',
                                       id_cliente_preseleccionado=id_cliente_para_asociar, # Pasa el ID seleccionado en el formulario
                                       cliente_actual=cliente_actual,
                                       clientes_disponibles=clientes_disponibles,
                                       vehiculo=request.form) # Pasa los datos del formulario para rellenar

            nuevo_vehiculo = Vehiculo(
                id_cliente=id_cliente_para_asociar, # Usa el ID del cliente seleccionado en el formulario
                patente=patente,
                marca=marca_vehiculo,
                modelo=modelo_vehiculo,
                anio=anio_vehiculo,
                kilometraje=kilometraje,
                notas_vehiculo=notas_vehiculo
            )
            db.session.add(nuevo_vehiculo)
            db.session.commit()
            flash('Vehículo agregado exitosamente!', 'success')
            return redirect(url_for('administrar_vehiculos_cliente', id_cliente=id_cliente_para_asociar))
            

        except Exception as e:
            db.session.rollback()
            flash(f'Error al agregar vehículo: {str(e)}', 'danger')
            print(f"Error al agregar vehículo: {e}")

    # Para solicitudes GET (cuando se carga la página de agregar vehículo)
    return render_template('formulario_vehiculo.html',
                           id_cliente_preseleccionado=id_cliente,
                           cliente_actual=cliente_actual,
                           clientes_disponibles=clientes_disponibles)

@app.route('/vehiculos/editar/<int:id_vehiculo>', methods=['GET', 'POST'])
@login_required
def editar_vehiculo(id_vehiculo):
    vehiculo = Vehiculo.query.get_or_404(id_vehiculo)
    
    # Obtenemos todos los clientes disponibles para el dropdown en la plantilla
    clientes_disponibles = Cliente.query.all() 

    if request.method == 'POST':
        # Mantengo tus nombres de campos para que coincidan con tu formulario
        vehiculo.marca = request.form['marca_vehiculo']
        vehiculo.modelo = request.form['modelo_vehiculo']
        vehiculo.anio = int(request.form['anio_vehiculo']) if request.form['anio_vehiculo'] else None
        vehiculo.kilometraje = int(request.form['kilometraje']) if request.form['kilometraje'] else None
        vehiculo.notas_vehiculo = request.form.get('notas_vehiculo')

        # Captura el nuevo ID del cliente seleccionado en el formulario
        nuevo_id_cliente = request.form.get('id_cliente', type=int) 
        
        # Asigna el nuevo ID de cliente al vehículo
        if nuevo_id_cliente: 
            vehiculo.id_cliente = nuevo_id_cliente

        try:
            db.session.commit()
            flash('Vehículo actualizado exitosamente!', 'success')
            return redirect(url_for('administrar_vehiculos_cliente', id_cliente=vehiculo.id_cliente))
        except Exception as e:
            db.session.rollback()
            flash(f'Error al actualizar vehículo: {str(e)}', 'danger')
            print(f"Error al actualizar vehículo: {e}")

    
    return render_template('formulario_vehiculo.html', 
                           vehiculo=vehiculo, 
                           clientes_disponibles=clientes_disponibles)

@app.route('/vehiculos/eliminar/<int:id_vehiculo>', methods=['POST'])
@login_required
def eliminar_vehiculo(id_vehiculo):
    vehiculo = Vehiculo.query.get_or_404(id_vehiculo)
    id_cliente = vehiculo.id_cliente # Guardamos el ID del cliente para redirigir correctamente

    try:
        db.session.delete(vehiculo)
        db.session.commit()
        flash('Vehículo eliminado exitosamente!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar vehículo: {str(e)}', 'danger')
        print(f"Error al eliminar vehículo: {e}")

    return redirect(url_for('administrar_vehiculos_cliente', id_cliente=id_cliente))

@app.route('/api/cliente/<int:id_cliente>/vehiculos', methods=['GET'])
@login_required # Si quieres que solo usuarios logeados puedan acceder a esta API
def get_vehiculos_por_cliente(id_cliente):
    # Obtener los vehículos asociados a este id_cliente
    vehiculos = Vehiculo.query.filter_by(id_cliente=id_cliente).all()
    
    # Formatear los datos de los vehículos para JSON
    vehiculos_data = [
        {
            'id_vehiculo': v.id_vehiculo,
            'patente': v.patente,
            'marca': v.marca,
            'modelo': v.modelo,
            'anio': v.anio # Asegúrate de que el nombre de la columna es 'anio'
        }
        for v in vehiculos
    ]
    return jsonify(vehiculos_data)

# --- Rutas para la Gestión de Órdenes de Trabajo ---

@app.route('/ordenes')
@login_required
def listar_ordenes():
    ordenes = OrdenTrabajo.query.options(
        db.joinedload(OrdenTrabajo.vehiculo).joinedload(Vehiculo.cliente)
    ).order_by(OrdenTrabajo.fecha_ingreso.desc()).all()
    return render_template('listar_ordenes.html', ordenes=ordenes)


@app.route('/ordenes/crear', methods=['GET', 'POST'])
@login_required
def crear_orden_trabajo():
    """Ruta para crear una nueva orden de trabajo."""
    
    # Preparamos los datos para el formulario GET o en caso de error en POST
    clientes = Cliente.query.order_by(Cliente.nombre_completo).all()
    repuestos_disponibles_obj = Repuesto.query.order_by(Repuesto.nombre_repuesto).all()
    repuestos_json_serializable = [
        {'id': r.id_repuesto, 'nombre_repuesto': r.nombre_repuesto, 'stock_actual': r.stock_actual, 'precio_venta': float(r.precio_venta)}
        for r in repuestos_disponibles_obj
    ]
    mecanicos = User.query.filter_by(role='mecanico').order_by(User.username).all()

    if request.method == 'POST':
        # Validar y convertir datos del formulario
        try:
            id_cliente = int(request.form.get('id_cliente'))
            id_vehiculo = int(request.form.get('id_vehiculo'))
            descripcion_trabajo = request.form.get('descripcion_trabajo')
            mecanico_asignado_id_str = request.form.get('mecanico_asignado')
            valor_mano_obra = float(request.form.get('valor_mano_obra', 0))
        except (ValueError, TypeError):
            flash('Error: Datos del formulario no válidos.', 'danger')
            return redirect(url_for('crear_orden_trabajo'))

        # Validar existencia de cliente y vehículo
        cliente = db.session.get(Cliente, id_cliente)
        vehiculo = db.session.get(Vehiculo, id_vehiculo)
        if not cliente or not vehiculo:
            flash('Error: Cliente o vehículo no encontrado.', 'danger')
            return redirect(url_for('crear_orden_trabajo'))
        
        mecanico_asignado = None
        if mecanico_asignado_id_str:
            try:
                mecanico_asignado_id = int(mecanico_asignado_id_str)
                mecanico = db.session.get(User, mecanico_asignado_id)
                if mecanico:
                    mecanico_asignado = mecanico.username
            except (ValueError, TypeError):
                flash('Error: Mecánico asignado no válido.', 'danger')
                return redirect(url_for('crear_orden_trabajo'))
        
        # --- Pre-validar repuestos antes de la transacción ---
        repuestos_ot_data = []
        valor_total_repuestos = 0
        for key in request.form:
            if key.startswith('repuesto_id_') and request.form[key]:
                try:
                    repuesto_id = int(request.form[key])
                    count = key.split('_')[2]
                    cantidad = int(request.form.get(f'cantidad_{count}', 0))
                    
                    if cantidad <= 0:
                        flash('Error: La cantidad de un repuesto debe ser mayor a 0.', 'danger')
                        return redirect(url_for('crear_orden_trabajo'))

                    repuesto_obj = db.session.get(Repuesto, repuesto_id)
                    if not repuesto_obj:
                        flash(f'Error: El repuesto con ID {repuesto_id} no fue encontrado.', 'danger')
                        return redirect(url_for('crear_orden_trabajo'))
                    
                    if repuesto_obj.stock_actual < cantidad:
                        flash(f'Stock insuficiente para "{repuesto_obj.nombre_repuesto}". Disponible: {repuesto_obj.stock_actual}, Solicitado: {cantidad}.', 'danger')
                        return redirect(url_for('crear_orden_trabajo'))

                    repuestos_ot_data.append({
                        'repuesto_obj': repuesto_obj,
                        'cantidad': cantidad,
                        'precio_venta_unitario': float(repuesto_obj.precio_venta)
                    })
                    valor_total_repuestos += repuesto_obj.precio_venta * cantidad
                
                except (ValueError, TypeError):
                    flash('Error: Datos de repuesto no válidos. Asegúrese de seleccionar un repuesto y una cantidad.', 'danger')
                    return redirect(url_for('crear_orden_trabajo'))
        
        # --- Si todo es válido, crear y guardar la Orden de Trabajo ---
        try:
            nueva_ot = OrdenTrabajo(
                id_vehiculo=id_vehiculo,
                fecha_ingreso=datetime.now(),
                descripcion_trabajo=descripcion_trabajo,
                mecanico_asignado=mecanico_asignado,
                valor_mano_obra=valor_mano_obra,
                valor_total_servicio=valor_mano_obra + valor_total_repuestos,
                estado='Pendiente'
            )
            db.session.add(nueva_ot)
            db.session.flush() # Importante: flush() para obtener el ID de la orden

            for item in repuestos_ot_data:
                # Crear el registro de la relación Repuesto-Orden (DetalleOT)
                detalle_ot = DetalleOT(
                    id_ot=nueva_ot.id_ot,
                    id_repuesto=item['repuesto_obj'].id_repuesto,
                    cantidad=item['cantidad'],
                    precio_unitario_al_momento=item['precio_venta_unitario']
                )
                db.session.add(detalle_ot)
                
                # Descontar del stock
                item['repuesto_obj'].stock_actual -= item['cantidad']
            
            db.session.commit()
            flash('Orden de Trabajo creada exitosamente.', 'success')
            return redirect(url_for('listar_ordenes'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error inesperado al crear la Orden de Trabajo: {str(e)}', 'danger')
            print(f"Error al crear OT: {e}") 

    # Renderiza el formulario si el método es GET o si hay un error
    return render_template('crear_orden_trabajo.html', 
                            clientes=clientes, 
                            repuestos_json=repuestos_json_serializable, 
                            mecanicos=mecanicos)


@app.route('/ordenes/ver/<int:id_ot>')
@login_required
def ver_orden_trabajo(id_ot):
    # Cargamos la OT y todos sus detalles relacionados para mostrarla
    ot = OrdenTrabajo.query.options(
        db.joinedload(OrdenTrabajo.vehiculo).joinedload(Vehiculo.cliente),
        db.joinedload(OrdenTrabajo.detalles_ot).joinedload(DetalleOT.repuesto)
    ).get_or_404(id_ot)
    return render_template('ver_orden_trabajo.html', ot=ot)

@app.route('/ordenes/finalizar/<int:id_ot>', methods=['POST'])
@login_required
def finalizar_orden_trabajo(id_ot):
    ot = OrdenTrabajo.query.get_or_404(id_ot)

    # Si la OT ya está finalizada, no hacer nada y mostrar un mensaje
    if ot.fecha_entrega_real:
        flash('Esta Orden de Trabajo ya ha sido finalizada.', 'info')
        return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ

    try:
        # 1. Marcar la Orden de Trabajo como finalizada
        ot.fecha_entrega_real = datetime.now()
        ot.estado = 'Completada' # Asegúrate de que el estado también se actualiza
        db.session.add(ot) # Marca la OT para ser guardada

        total_venta_ot = ot.valor_mano_obra if ot.valor_mano_obra is not None else 0.0

        # 2. Obtener los detalles de repuestos de esta OT
        detalles_ot = DetalleOT.query.filter_by(id_ot=ot.id_ot).all()

        # 3. Validar stock final y calcular el total de repuestos
        for detalle_ot_item in detalles_ot:
            repuesto = Repuesto.query.get(detalle_ot_item.id_repuesto)
            if not repuesto:
                flash(f'Error: Repuesto con ID {detalle_ot_item.id_repuesto} no encontrado para la OT {ot.id_ot}.', 'danger')
                db.session.rollback()
                return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ
            
            if repuesto.stock_actual < detalle_ot_item.cantidad:
                flash(f'No se pudo finalizar la OT: Stock insuficiente para "{repuesto.nombre_repuesto}". Disponible: {repuesto.stock_actual}, Requerido: {detalle_ot_item.cantidad}. La OT no se finalizó.', 'danger')
                db.session.rollback()
                return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ

            total_venta_ot += (detalle_ot_item.cantidad * detalle_ot_item.precio_unitario_al_momento)

        # 4. Crear el registro de Venta asociado a la OT
        id_cliente_venta = None
        if ot.vehiculo and ot.vehiculo.cliente: # Asegura que vehiculo y cliente existen
            id_cliente_venta = ot.vehiculo.cliente.id_cliente

        nueva_venta_ot = Venta(
            id_cliente=id_cliente_venta,
            total_venta=total_venta_ot,
            tipo_venta='Servicio y Repuestos OT',
            id_ot_asociada=ot.id_ot,
            saldo_pendiente=total_venta_ot # El saldo pendiente al finalizar es el total de la venta
        )
        db.session.add(nueva_venta_ot)
        db.session.flush() # Para asignar el id_venta

        # 5. Crear los DetalleVenta para cada repuesto de la OT y descontar stock
        for detalle_ot_item in detalles_ot:
            detalle_venta_ot = DetalleVenta(
                id_venta=nueva_venta_ot.id_venta,
                id_repuesto=detalle_ot_item.id_repuesto,
                cantidad=detalle_ot_item.cantidad,
                precio_venta_unitario_al_momento=detalle_ot_item.precio_unitario_al_momento
            )
            db.session.add(detalle_venta_ot)

            repuesto = Repuesto.query.get(detalle_ot_item.id_repuesto)
            repuesto.stock_actual -= detalle_ot_item.cantidad
            db.session.add(repuesto) # Marca el repuesto para ser actualizado

        # 6. Realizar el commit de todos los cambios
        db.session.commit()
        flash('Orden de Trabajo finalizada, Venta generada y stock actualizado exitosamente.', 'success')
        return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ

    except Exception as e:
        db.session.rollback()
        flash(f'Error al finalizar la Orden de Trabajo: {str(e)}. La OT no se finalizó.', 'danger')
        print(f"Error al finalizar OT y generar venta: {e}")
        return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ

    # Este return de respaldo SOLO se alcanzará si, por alguna razón muy inusual,
    # ninguna de las sentencias 'return' anteriores fue ejecutada.
    flash('Un error inesperado ocurrió al finalizar la Orden de Trabajo. Por favor, inténtalo de nuevo.', 'danger')
    return redirect(url_for('ver_orden_trabajo', id_ot=ot.id_ot)) # <--- CORREGIDO AQUÍ

@app.route('/ordenes/eliminar/<int:id_ot>', methods=['POST'])
@login_required
def eliminar_orden_trabajo(id_ot):
    ot = OrdenTrabajo.query.get_or_404(id_ot)

    try:
        # Reintegrar stock de repuestos si la OT se elimina
        for detalle in ot.detalles_ot:
            repuesto = Repuesto.query.get(detalle.id_repuesto)
            if repuesto: # Asegurarse que el repuesto aún existe
                repuesto.stock_actual += detalle.cantidad
                db.session.add(repuesto)
        
        db.session.delete(ot) # Gracias al cascade en el modelo, DetalleOT se elimina automáticamente
        db.session.commit()
        flash('Orden de Trabajo eliminada exitosamente y stock de repuestos reintegrado!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al eliminar Orden de Trabajo: {str(e)}', 'danger')
        print(f"Error al eliminar OT: {e}")
    return redirect(url_for('listar_ordenes'))

@app.route('/historial_vehiculo', methods=['GET', 'POST'])
@login_required
def historial_vehiculo():
    ordenes_encontradas = []
    patente_buscada = None

    if request.method == 'POST':
        patente_buscada = request.form.get('patente_buscada')
        if patente_buscada:
            # Buscar el vehículo (o vehículos, si permitiéramos patentes no únicas)
            # que coincidan con la patente. Usamos first() porque la patente es única.
            vehiculo = Vehiculo.query.filter_by(patente=patente_buscada.upper()).first() # .upper() para hacer la búsqueda insensible a mayúsculas/minúsculas

            if vehiculo:
                # Si el vehículo existe, obtener todas las Órdenes de Trabajo asociadas a él
                ordenes_encontradas = OrdenTrabajo.query.filter_by(id_vehiculo=vehiculo.id_vehiculo).order_by(OrdenTrabajo.fecha_ingreso.desc()).all()
            else:
                flash(f'No se encontró ningún vehículo con la patente "{patente_buscada}".', 'warning')
        else:
            flash('Por favor, ingresa una patente para buscar.', 'danger')

    return render_template('historial_vehiculo.html', 
                           ordenes_encontradas=ordenes_encontradas,
                           patente_buscada=patente_buscada)

# --- Rutas para la Gestión de Ventas Directas ---

@app.route('/ventas/crear_directa', methods=['GET'])
@login_required
@role_required(['admin', 'cajero'])
def crear_venta_directa():
    # Para el formulario, necesitamos la lista de repuestos disponibles
    repuestos_disponibles = Repuesto.query.all()
    clientes_disponibles = Cliente.query.all() # Para asociar la venta a un cliente (opcional)

    # El carrito de compras se guardará en la sesión de Flask
    # Si la sesión no tiene 'carrito_venta_directa', inicialízalo como una lista vacía
    carrito = session.get('carrito_venta_directa', [])

    # Para mostrar el nombre del repuesto y cliente en el carrito, obtenemos sus objetos
    items_en_carrito = []
    for item in carrito:
        repuesto = Repuesto.query.get(item['id_repuesto'])
        if repuesto:
            items_en_carrito.append({
                'id_repuesto': item['id_repuesto'],
                'nombre_repuesto': repuesto.nombre_repuesto,
                'cantidad': item['cantidad'],
                'precio_venta_unitario': repuesto.precio_venta, # Usamos el precio actual para mostrar
                'subtotal': item['cantidad'] * repuesto.precio_venta
            })
    
    total_carrito = sum(item['subtotal'] for item in items_en_carrito)

    return render_template('crear_venta_directa.html',
                           repuestos=repuestos_disponibles,
                           clientes=clientes_disponibles,
                           items_en_carrito=items_en_carrito,
                           total_carrito=total_carrito)

# En app.py, dentro de tu función 'agregar_item_a_venta'
# ...
@app.route('/agregar_item_a_venta', methods=['POST'])
@login_required
@role_required(['admin', 'cajero'])
def agregar_item_a_venta():
    if request.method == 'POST':
        id_repuesto = request.form.get('id_repuesto')
        cantidad_solicitada = int(request.form.get('cantidad', 1)) # Renombré para mayor claridad

        if not id_repuesto:
            return jsonify({'success': False, 'message': 'Repuesto no seleccionado.'}), 400

        repuesto = db.session.get(Repuesto, id_repuesto) # Usando db.session.get para la advertencia LegacyAPIWarning

        if not repuesto:
            return jsonify({'success': False, 'message': 'Repuesto no encontrado.'}), 404

        if cantidad_solicitada <= 0:
            return jsonify({'success': False, 'message': 'La cantidad debe ser al menos 1.'}), 400

        # Preparamos el nuevo ítem, independientemente de si ya está en el carrito
        item_a_agregar = {
            'id_repuesto': repuesto.id_repuesto,
            'nombre_repuesto': repuesto.nombre_repuesto,
            'cantidad': cantidad_solicitada, # Usamos la cantidad directamente del formulario
            'precio_venta_unitario': repuesto.precio_venta,
            'subtotal': cantidad_solicitada * repuesto.precio_venta
        }

        if 'carrito_venta_directa' not in session:
            session['carrito_venta_directa'] = []
        
        found = False
        for i, cart_item in enumerate(session['carrito_venta_directa']):
            if cart_item['id_repuesto'] == item_a_agregar['id_repuesto']:
                # *** ¡CAMBIO CRUCIAL AQUÍ! ***
                # Reemplazamos la cantidad existente con la cantidad_solicitada
                # Primero, verificar si la cantidad solicitada (reemplazada) excede el stock
                if repuesto.stock_actual < cantidad_solicitada:
                    return jsonify({'success': False, 'message': f'Stock insuficiente. Disponible: {repuesto.stock_actual}, Requerido: {cantidad_solicitada}.'}), 400

                session['carrito_venta_directa'][i]['cantidad'] = cantidad_solicitada
                session['carrito_venta_directa'][i]['subtotal'] = cantidad_solicitada * repuesto.precio_venta
                found = True
                break
        
        if not found:
            # Si el ítem no estaba en el carrito, lo agregamos (después de la verificación inicial de stock)
            if repuesto.stock_actual < cantidad_solicitada: # Esta verificación se repite, pero asegura stock si es item nuevo
                return jsonify({'success': False, 'message': f'Stock insuficiente. Disponible: {repuesto.stock_actual}, Requerido: {cantidad_solicitada}.'}), 400
            session['carrito_venta_directa'].append(item_a_agregar)
        
        session.modified = True # ¡Importante para que Flask sepa que la sesión ha cambiado!

        # Calcular el total del carrito para la respuesta
        total_carrito = sum(item['subtotal'] for item in session['carrito_venta_directa'])

        # Renderizar la tabla del carrito como una cadena HTML
        carrito_html = render_template('_carrito_items_tabla.html', 
                                       items_en_carrito=session['carrito_venta_directa'],
                                       total_carrito=total_carrito,
                                       clp=format_clp) # Asegúrate de pasar el filtro si es custom

        # Devolver una respuesta JSON
        return jsonify({
            'success': True,
            'message': 'Ítem agregado/actualizado en el carrito.',
            'carrito_html': carrito_html,
            'total_carrito': total_carrito,
            'total_carrito_clp': format_clp(total_carrito), 
            'total_items': len(session['carrito_venta_directa'])
        })

    return jsonify({'success': False, 'message': 'Método no permitido.'}), 405


def format_clp(value):
    return f"{value:,.0f}".replace(",", "X").replace(".", ",").replace("X", ".")

@app.route('/ventas/eliminar_item_de_venta/<int:id_repuesto_a_eliminar>', methods=['POST'])
@login_required 
@role_required(['admin', 'cajero'])
def eliminar_item_de_venta(id_repuesto_a_eliminar):
    if 'carrito_venta_directa' in session:
        # Crea una nueva lista de carrito excluyendo el ítem a eliminar
        # Esto es más seguro que .pop(index) porque no depende de la posición.
        initial_len = len(session['carrito_venta_directa'])
        session['carrito_venta_directa'] = [
            item for item in session['carrito_venta_directa'] 
            if item['id_repuesto'] != id_repuesto_a_eliminar
        ]

        if len(session['carrito_venta_directa']) < initial_len:
            session.modified = True # Marcar sesión como modificada
            flash(f'Ítem eliminado del carrito.', 'info')
        else:
            flash('Ítem no encontrado en el carrito.', 'danger')
    else:
        flash('El carrito está vacío.', 'info')

    return redirect(url_for('crear_venta_directa'))

@app.route('/ventas/vaciar_venta', methods=['POST'])
@role_required(['admin', 'cajero'])
def vaciar_venta():
    if 'carrito_venta_directa' in session:
        session.pop('carrito_venta_directa', None) # Elimina el carrito de la sesión
        session.modified = True # Marcar sesión como modificada
        flash('El carrito de compras ha sido vaciado.', 'info')
    return redirect(url_for('crear_venta_directa'))

@app.route('/ventas/finalizar_venta_directa', methods=['POST'])
@login_required 
@role_required(['admin', 'cajero'])
def finalizar_venta_directa():
    if 'carrito_venta_directa' not in session or not session['carrito_venta_directa']:
        flash('El carrito está vacío, no se puede finalizar la venta.', 'danger')
        return redirect(url_for('crear_venta_directa'))

    id_cliente = request.form.get('id_cliente_venta', type=int)
    tipo_venta = request.form.get('tipo_venta', 'Repuesto Directo')
    
    # --- ¡NUEVO: Obtener el método de pago del formulario! ---
    # Se obtiene el valor del campo 'metodo_pago' del formulario.
    # Si no se envía por alguna razón, se usa 'Efectivo' como valor por defecto.
    metodo_pago = request.form.get('metodo_pago', 'Efectivo') 

    total_venta = 0.0
    detalles_a_guardar = []
    
    # Recorrer los ítems del carrito, verificar el stock y calcular el total
    for item_data in session['carrito_venta_directa']:
        repuesto = db.session.get(Repuesto, item_data['id_repuesto']) 

        if not repuesto:
            flash(f'Error: Repuesto con ID {item_data["id_repuesto"]} no encontrado. Venta no completada.', 'danger')
            db.session.rollback()
            session.modified = True
            return redirect(url_for('crear_venta_directa'))
            
        if repuesto.stock_actual < item_data['cantidad']:
            flash(f'Error al finalizar: Stock insuficiente para "{repuesto.nombre_repuesto}" (Disponible: {repuesto.stock_actual}, Solicitado: {item_data["cantidad"]}). Venta no completada.', 'danger')
            db.session.rollback()
            session.modified = True
            return redirect(url_for('crear_venta_directa'))
        
        subtotal_item = item_data['cantidad'] * item_data['precio_venta_unitario'] 
        total_venta += subtotal_item
        detalles_a_guardar.append((repuesto, item_data))

    try:
        # Crear la Venta principal
        nueva_venta = Venta(
            id_cliente=id_cliente if id_cliente else None,
            total_venta=total_venta,
            tipo_venta=tipo_venta,
            saldo_pendiente=0.0, # Saldo pendiente es 0 porque se paga al finalizar
            fecha_venta=datetime.now(pytz.timezone('America/Santiago')) # Usar la zona horaria correcta de Chile
        )
        db.session.add(nueva_venta)
        db.session.flush() # Para que nueva_venta.id_venta esté disponible

        # Guardar los detalles de la venta y actualizar stock
        for repuesto_obj, item_data in detalles_a_guardar:
            detalle_venta = DetalleVenta(
                id_venta=nueva_venta.id_venta,
                id_repuesto=item_data['id_repuesto'],
                cantidad=item_data['cantidad'],
                precio_venta_unitario_al_momento=item_data['precio_venta_unitario'] 
            )
            db.session.add(detalle_venta)
            
            repuesto_obj.stock_actual -= item_data['cantidad']
            db.session.add(repuesto_obj)

        # --- ¡LÓGICA PARA REGISTRAR EL PAGO CON EL MÉTODO SELECCIONADO! ---
        if total_venta > 0: # Solo crear un pago si el total es mayor a 0
            nuevo_pago = Pago(
                id_venta=nueva_venta.id_venta,
                monto=total_venta, 
                fecha_pago=datetime.now(), # Usando datetime.now() como en tu modelo de Pago
                metodo_pago=metodo_pago, # <--- ¡Aquí se usa el valor del formulario!
                descripcion=f'Pago por Venta Directa #{nueva_venta.id_venta}' 
            )
            db.session.add(nuevo_pago)
        # --- FIN LÓGICA DE PAGO ---

        db.session.commit()
        
        session.pop('carrito_venta_directa', None) 
        session.modified = True 

        flash('Venta directa finalizada, pago registrado y stock actualizado.', 'success')
        return redirect(url_for('crear_venta_directa')) # Se mantiene en la misma página

    except Exception as e:
        db.session.rollback()
        flash(f'Error al finalizar la venta: {str(e)}', 'danger')
        print(f"Error al finalizar venta: {e}")
        session.modified = True 
        return redirect(url_for('crear_venta_directa'))

    
# --- Rutas para Listado y Detalle de Ventas ---

@app.route('/ventas')
@login_required
@role_required(['admin', 'cajero'])
def listar_ventas():
    ventas = Venta.query.order_by(Venta.fecha_venta.desc()).all()
    return render_template('listar_ventas.html', ventas=ventas)

@app.route('/ventas/ver/<int:id_venta>')
@login_required
@role_required(['admin', 'cajero'])
def ver_venta(id_venta):
    venta = Venta.query.get_or_404(id_venta)
    return render_template('ver_venta.html', venta=venta)

# --- Rutas para la Gestión de Pagos ---

@app.route('/pagos')
@login_required
@role_required(['admin', 'cajero'])
def listar_pagos():
    pagos = Pago.query.order_by(Pago.fecha_pago.desc()).all()
    return render_template('listar_pagos.html', pagos=pagos)

@app.route('/pagos/crear', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'cajero'])
def crear_pago():
    ventas_disponibles = Venta.query.order_by(Venta.fecha_venta.desc()).all()
    id_venta_preseleccionada = request.args.get('id_venta_preseleccionada', type=int)

    if request.method == 'POST':
        id_venta = request.form.get('id_venta', type=int)
        monto = request.form.get('monto', type=float)
        metodo_pago = request.form.get('metodo_pago')
        descripcion = request.form.get('descripcion')

        if not id_venta or monto is None or monto <= 0 or not metodo_pago:
            flash('Datos de pago incompletos o inválidos.', 'danger')
            return redirect(url_for('crear_pago'))

        venta = Venta.query.get(id_venta)
        if not venta:
            flash('Venta asociada no encontrada.', 'danger')
            return redirect(url_for('crear_pago'))

        saldo_actual_venta = venta.saldo_pendiente

        if monto > saldo_actual_venta:
            flash(f'El monto del pago ({int(monto)}) excede el saldo pendiente ({int(saldo_actual_venta)}).', 'danger')
            # Redirigir y rellenar el formulario para que el usuario corrija
            return render_template('crear_pago.html',
                                   ventas=ventas_disponibles,
                                   id_venta_preseleccionada=id_venta,
                                   monto_ingresado=monto,
                                   metodo_pago_seleccionado=metodo_pago,
                                   descripcion_ingresada=descripcion)
        
        
        if abs(saldo_actual_venta - monto) < 0.01: 
             monto = saldo_actual_venta 
             saldo_final_despues_pago = 0.0
        else:
            saldo_final_despues_pago = saldo_actual_venta - monto

        try:
            
            nuevo_pago = Pago(
                id_venta=id_venta,
                monto=monto,
                metodo_pago=metodo_pago,
                descripcion=descripcion
            )
            db.session.add(nuevo_pago)

            
            venta.saldo_pendiente = saldo_final_despues_pago
            db.session.add(venta) # Marcar la venta para ser guardada

            if venta.id_ot_asociada:
                ot_asociada = OrdenTrabajo.query.get(venta.id_ot_asociada)
                if ot_asociada and venta.saldo_pendiente <= 0:
                    ot_asociada.estado = 'Pagada'
                    db.session.add(ot_asociada)

            db.session.commit()
            flash('Pago registrado exitosamente.', 'success')
            return redirect(url_for('listar_pagos')) 

        except Exception as e:
            db.session.rollback()
            flash(f'Error al registrar el pago: {str(e)}', 'danger')
            print(f"Error al crear pago: {e}")

    return render_template('crear_pago.html',
                           ventas=ventas_disponibles,
                           id_venta_preseleccionada=id_venta_preseleccionada)

@app.route('/ordenes/registrar-pago/<int:id_ot>', methods=['POST'])
@login_required
def registrar_pago(id_ot):
    """
    Ruta para registrar el pago de una orden de trabajo.
    Solo acepta peticiones POST y cambia el estado de la orden a 'Pagada'.
    """
    orden = db.session.get(OrdenTrabajo, id_ot)
    if not orden:
        flash('Error: Orden de trabajo no encontrada.', 'danger')
        return redirect(url_for('listar_ordenes'))

    # Se verifica si la orden está en estado 'Completada' antes de registrar el pago.
    if orden.estado != 'Completada':
        flash('Error: Solo se pueden registrar pagos de órdenes completadas.', 'danger')
        return redirect(url_for('listar_ordenes'))
    
    # Se cambia el estado de la orden a 'Pagada'
    orden.estado = 'Pagada'
    
    try:
        db.session.commit()
        flash(f'El pago de la Orden de Trabajo #{id_ot} ha sido registrado exitosamente.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error al registrar el pago: {str(e)}', 'danger')
        print(f"Error al registrar pago de OT {id_ot}: {e}")
    
    return redirect(url_for('listar_ordenes'))


# --- Rutas para Reportes ---

@app.route('/reportes/stock_minimo')
@login_required
@role_required(['admin', 'cajero'])
def reporte_stock_minimo():
    # Obtener repuestos cuyo stock_actual es menor o igual al stock_minimo
    repuestos_bajo_minimo = Repuesto.query.filter(Repuesto.stock_actual <= Repuesto.stock_minimo).order_by(Repuesto.nombre_repuesto).all()
    return render_template('reporte_stock_minimo.html', repuestos=repuestos_bajo_minimo)

@app.route('/reportes/ventas_periodo', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def reporte_ventas_periodo():
    ventas = []
    fecha_inicio_str = request.args.get('fecha_inicio') # Para GET (enlace directo o después de POST)
    fecha_fin_str = request.args.get('fecha_fin')       # Para GET

    if request.method == 'POST':
        fecha_inicio_str = request.form.get('fecha_inicio')
        fecha_fin_str = request.form.get('fecha_fin')

    fecha_inicio = None
    fecha_fin = None
    total_ventas_periodo = 0.0

    try:
        if fecha_inicio_str:
            # Intenta parsear la fecha de inicio. La hora por defecto será 00:00:00
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
        if fecha_fin_str:
            # Intenta parsear la fecha de fin. La hora por defecto será 00:00:00
            # Para incluir todo el día, ajustamos la fecha de fin al final del día.
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)

        query = Venta.query

        if fecha_inicio:
            query = query.filter(Venta.fecha_venta >= fecha_inicio)
        if fecha_fin:
            query = query.filter(Venta.fecha_venta <= fecha_fin)

        ventas = query.order_by(Venta.fecha_venta.desc()).all()
        total_ventas_periodo = sum(venta.total_venta for venta in ventas)

    except ValueError:
        flash('Formato de fecha inválido. Por favor, usa AAAA-MM-DD.', 'danger')
        # Reiniciar para que no se muestre ningún resultado si la fecha es inválida
        ventas = []
        fecha_inicio_str = ""
        fecha_fin_str = ""
        total_ventas_periodo = 0.0
    except Exception as e:
        flash(f'Ocurrió un error al generar el reporte: {str(e)}', 'danger')
        print(f"Error en reporte_ventas_periodo: {e}")
        ventas = []
        fecha_inicio_str = ""
        fecha_fin_str = ""
        total_ventas_periodo = 0.0

    return render_template('reporte_ventas_periodo.html',
                           ventas=ventas,
                           fecha_inicio_str=fecha_inicio_str,
                           fecha_fin_str=fecha_fin_str,
                           total_ventas_periodo=total_ventas_periodo)

@app.route('/reportes/ot_por_estado', methods=['GET'])
@login_required
def reporte_ot_por_estado():
    # Consulta todas las órdenes de trabajo
    ordenes = OrdenTrabajo.query.all()

    # Contar órdenes por estado
    conteo_por_estado = {}
    for ot in ordenes:
        estado_actual = ot.estado
        if estado_actual in conteo_por_estado:
            conteo_por_estado[estado_actual] += 1
        else:
            conteo_por_estado[estado_actual] = 1

    # Opcional: Si quieres un orden específico para los estados
    # estados_ordenados = ['Pendiente', 'En Progreso', 'Finalizada', 'Cancelada']
    # conteo_final_ordenado = {estado: conteo_por_estado.get(estado, 0) for estado in estados_ordenados}

    return render_template('reporte_ot_por_estado.html', conteo_por_estado=conteo_por_estado)

@app.route('/reportes/ingresos_por_periodo', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])

def reporte_ingresos_por_periodo():
    ingresos_por_dia = {}
    fecha_inicio_str = None
    fecha_fin_str = None

    if request.method == 'POST':
        fecha_inicio_str = request.form.get('fecha_inicio')
        fecha_fin_str = request.form.get('fecha_fin')

        if not fecha_inicio_str or not fecha_fin_str:
            flash('Por favor, ingresa ambas fechas para el reporte.', 'danger')
            return render_template('reporte_ingresos_por_periodo.html', ingresos_por_dia=ingresos_por_dia)

        try:
            # Convertir las fechas de string a objeto datetime
            fecha_inicio = datetime.strptime(fecha_inicio_str, '%Y-%m-%d')
            fecha_fin = datetime.strptime(fecha_fin_str, '%Y-%m-%d') + timedelta(days=1) # Sumar 1 día para incluir el día final completo

            # Obtener todos los pagos dentro del rango de fechas
            pagos = Pago.query.filter(Pago.fecha_pago >= fecha_inicio, Pago.fecha_pago < fecha_fin).order_by(Pago.fecha_pago).all()

            # Agrupar ingresos por día
            for pago in pagos:
                dia = pago.fecha_pago.strftime('%Y-%m-%d') # Formato 'YYYY-MM-DD'
                if dia not in ingresos_por_dia:
                    ingresos_por_dia[dia] = 0
                ingresos_por_dia[dia] += pago.monto

        except ValueError:
            flash('Formato de fecha inválido. Usa YYYY-MM-DD.', 'danger')
        except Exception as e:
            flash(f'Error al generar el reporte: {str(e)}', 'danger')

    # Ordenar los días para la tabla en la plantilla
    ingresos_ordenados = sorted(ingresos_por_dia.items())

    # Calcular el total de ingresos para el período seleccionado
    total_ingresos_periodo = sum(monto for dia, monto in ingresos_ordenados)

    return render_template('reporte_ingresos_por_periodo.html', 
                           ingresos_por_dia=ingresos_ordenados,
                           total_ingresos_periodo=total_ingresos_periodo,
                           fecha_inicio_str=fecha_inicio_str,
                           fecha_fin_str=fecha_fin_str)

@app.route('/reportes/repuestos_mas_vendidos', methods=['GET'])
@login_required
@role_required(['admin', 'cajero'])
def reporte_repuestos_mas_vendidos():
    # Consulta todos los detalles de órdenes de trabajo
    todos_los_detalles_ot = DetalleOT.query.all()

    # Diccionario para almacenar la cantidad total vendida de cada repuesto
    conteo_repuestos = {} # {id_repuesto: cantidad_total}

    for detalle in todos_los_detalles_ot:
        if detalle.repuesto: # Asegúrate de que el repuesto exista
            id_repuesto = detalle.id_repuesto
            cantidad_vendida = detalle.cantidad

            if id_repuesto in conteo_repuestos:
                conteo_repuestos[id_repuesto] += cantidad_vendida
            else:
                conteo_repuestos[id_repuesto] = cantidad_vendida

    # Obtener los objetos Repuesto para mostrar sus nombres
    repuestos_info = {}
    for id_repuesto, cantidad_total in conteo_repuestos.items():
        repuesto = Repuesto.query.get(id_repuesto)
        if repuesto:
            repuestos_info[repuesto.nombre_repuesto] = cantidad_total # Usar el nombre del repuesto como clave

    # Ordenar los repuestos por la cantidad vendida en orden descendente
    repuestos_mas_vendidos_ordenados = sorted(repuestos_info.items(), key=lambda item: item[1], reverse=True)

    return render_template('reporte_repuestos_mas_vendidos.html', 
                           repuestos_mas_vendidos=repuestos_mas_vendidos_ordenados)

# --- Iniciar la Aplicación ---
if __name__ == '__main__':
    # Esto crea las tablas en la base de datos si no existen
    with app.app_context():
        db.create_all()
    app.run(debug=True) # debug=True permite ver errores y recargar automáticamente