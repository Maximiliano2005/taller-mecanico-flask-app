from app import app, db

@app.cli.command('create-db')
def create_db():
    """Crea las tablas de la base de datos."""
    with app.app_context():
        db.create_all()
        print('Base de datos creada!')
