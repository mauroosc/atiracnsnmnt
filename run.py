from app import create_app
import psycopg2
from dotenv import load_dotenv
import os
load_dotenv()







class database ():
    
    conexion = None
    db = None


    def conectar (self):
        self.conexion = psycopg2.connect (os.environ.get('psql'))
        self.db = self.conexion.cursor()


    def desconectar (self):
        self.conexion.commit()
        self.db.close()
        self.conexion.close()

database_api = database ()

app = create_app(database_api)

if __name__ == '__main__':
    app.run(debug=True)
