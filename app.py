from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from models import mongo, init_db
from config import Config
from bson.json_util import ObjectId 
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config.from_object(Config)

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

init_db(app)

# Definir endpoint para registrar un usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if mongo.db.users.find_one({"email": email}):
        return jsonify({"msg": "Este usuario ya está registrado"}), 400
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    result = mongo.db.users.insert_one({"username":username, "email":email, "password":hashed_password})
    if result.acknowledged:
        return jsonify({"msg":"Usuario creado correctamente"}), 201
    else:
        return jsonify({"msg":"Hubo un error, no se pudieron guardar los datos"}), 400
    
@app.route('/users', methods=['GET'])
def showusers():
    users = mongo.db.users.find({},{"_id":0, "username":1, "email":1})
    list_users = list(users)
    print(list_users)

    if list_users:
        return jsonify(list_users), 200
    else:
        return jsonify({"msg":"No hay usuarios"}), 404

@app.route('/users', methods=['DELETE'])
def deleteuser():

    data = request.get_json()
    email = data.get('email')

    result = mongo.db.users.delete_one({"email": email})
    
    if result.deleted_count > 0:
        return jsonify({"msg": "El usuario fue borrado exitosamente"}), 200
    else:
        return jsonify({"msg": "No se encontró el usuario con el correo proporcionado"}), 404

# Endpoint para login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print(data)
    email = data.get('email')
    password = data.get('password')

    user = mongo.db.users.find_one({"email": email})
    
    if user and bcrypt.check_password_hash(user['password'], password):
        access_token = create_access_token(identity=str(user["_id"]))
        return jsonify(access_token=access_token), 200
    
    else:
        return jsonify({"msg": "Credenciales incorrectas"}), 401


if __name__ == '__main__':
    app.run(debug=True)