from app import app, db, User

with app.app_context():
    if not User.query.filter_by(username='maxi').first():
        nuevo_usuario = User(username='maxi', role='mecanico')
        nuevo_usuario.set_password('1234')
        db.session.add(nuevo_usuario)
        db.session.commit()
        print("Usuario 'maxi' creado con contraseña '1234'")
    else:
        print("El usuario 'maxi' ya existe")