from app import app, db, User

with app.app_context():
    if not User.query.filter_by(username='admin').first():
        nuevo_usuario = User(username='admin', role='admin')
        nuevo_usuario.set_password('adminpass2025')
        db.session.add(nuevo_usuario)
        db.session.commit()
        print("Usuario 'admin' creado con contraseña 'adminpass2025'")
    else:
        print("El usuario 'admin' ya existe")