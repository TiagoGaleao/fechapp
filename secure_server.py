from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
import requests
from webargs.flaskparser import parser, use_args
from coms_parser import *
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps

import random, string
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = "this_is_my_secrete" 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database_secure.db'
db = SQLAlchemy(app)

#query
#db.query.get(id=....)

#db.drop_all()
# adicionar cenas na db
# db.session.add()

class Fechadura(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    address = db.Column(db.String(80), nullable = False)
    nome = db.Column(db.String(30), nullable = False)

    def to_dict(self):
        return {"id": self.id, "address":self.address, "nome":self.nome}

    def __repr__(self):
        return f"Fechadura(id={self.id}, endereco={self.address}, nome={self.nome})"


class User(db.Model):
    numtel = db.Column(db.String(12), primary_key = True)
    cripto = db.Column(db.String(80), nullable = False)
    nome = db.Column(db.String(30), nullable = False)

    def to_dict(self):
        return {"NumTel": self.numtel, "Pass":self.cripto, "nome":self.nome}

    def __repr__(self):
        return f"User(id={self.numtel}, endereco={self.cripto}, nome={self.nome})"


class Dono(db.Model):
    ID = db.Column(db.Integer, db.ForeignKey('fechadura.id'), primary_key=True)
    NUser = db.Column(db.String(12), db.ForeignKey('user.numtel'), primary_key=True)
    fechadura = db.relationship('Fechadura', backref=db.backref('donos'))
    user = db.relationship('User', backref=db.backref('donos'))

    def to_dict(self):
        return {"ID": self.ID, "TelDono":self.NUser}

    def __repr__(self):
        return f"Dono(ID={self.ID}, NUser={self.NUser})"


tags = db.Table( 'tags', db.metadata,
    db.Column('NUser', db.String, db.ForeignKey('dono.NUser'), primary_key = True),
    db.Column('ID', db.Integer, db.ForeignKey('dono.ID'), primary_key = True)
)

class Autenticacao(db.Model):
    Codigo = db.Column(db.String(120), primary_key = True)
    Momento = db.Column(db.DateTime, primary_key = True)
    ID = db.Column(db.Integer, db.ForeignKey('dono.ID'), primary_key = True)
    NUser = db.Column(db.String(12), db.ForeignKey('dono.NUser'), primary_key = True)
    pin = db.Column(db.String(12))
    __table_args__ = (
        db.ForeignKeyConstraint(
            ['ID', 'NUser'],
            ['dono.ID', 'dono.NUser'],
        ),
    )
    dono = db.relationship('Dono', foreign_keys=[ID, NUser], backref = db.backref('autenticacao'))
    Friend = db.Column(db.String(12), db.ForeignKey('user.numtel'))
    user = db.relationship('User', backref=db.backref('autenticacao'))

#Momento={self.Momento},
    def to_dict(self):
        return {"Codigo": self.Codigo, "Momento":self.Momento, "NumDono":self.NUser, "IDFech":self.ID, "Friend":self.Friend}

    def __repr__(self):
        return f"Autenticacao(Codigo={self.Codigo}, NumDono={self.NUser}, IDFech={self.ID}, Friend={self.Friend})"

class Evento(db.Model):
    time = db.Column(db.DateTime, primary_key=True)
    ID = db.Column(db.Integer, db.ForeignKey('fechadura.id'), primary_key=True)
    fechadura = db.relationship('Fechadura', backref=db.backref('evento'))
    description = db.Column(db.String(100), nullable=False)

    @staticmethod
    def add_evento(id, descr):
        now = datetime.now()
        acontece = Evento(time = now, ID = id, description = descr)
        db.session.add(acontece)

    def to_dict(self):
        return {"time":self.time, "ID":self.ID, "description":self.description}

    def __repr__(self):
        return f"Evento(time={self.time}, ID={self.ID}, description={self.description})"

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-acess-token' in request.headers:
            token = request.headers['x-acess-token']
        
        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
            current_user = User.query.filter_by(numtel = data['numtel']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated












db.create_all()
db.session.commit()

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        print("Erro1")
        return make_response("could not verify", 401, {'WWW-Authenticate' : 'Basic realm = "Login requeired!"'})

    user = User.query.filter_by(numtel = auth.username).first()

    if not user:
        print("Erro2")
        return make_response("could not verify", 401, {'WWW-Authenticate' : 'Basic realm = "Login requeired!"'})
    
    if check_password_hash(user.cripto, auth.password):
        token = jwt.encode({"numtel" : user.numtel, 'exp' : datetime.utcnow() + timedelta(minutes=10)}, app.config['SECRET_KEY'], algorithm="HS256")
        print(token)
        return jsonify({'token' : token})
    
    print("Erro3")
    return make_response("could not veriify", 401, {'WWW-Authenticate' : 'Basic realm = "Login requeired!"'})      



@app.route('/', methods=['GET'])
def home():
    return {'data':'Hello'}

@app.route('/add_lock', methods=['PUT'])
#@use_args(lock_parse)
def add_lock():
    args = parser.parse(lock_parse, request)
    try:
        lock = Fechadura(id = args['id'], address = args['address'], nome = args['nome'])
        Evento.add_evento(args['id'], "Criar fechadura")
        #print(lock)
        #print(args)
        db.session.add(lock)
        db.session.commit()
        return jsonify({'message': "Lock added"})
    except:
        return jsonify("Unable to add lock"), 409

@app.route('/get_lock', methods=['GET'])
def get_lock():
    if 'id' in request.args:
        id_lock = int(request.args["id"])
        lock = Fechadura.query.filter_by(id=id_lock).first()
        print(lock)
        return(jsonify(lock.to_dict()))
    return("Error")


@app.route('/add_user', methods=['PUT'])
#@use_args(lock_parse)
def add_user():
    args = parser.parse(user_parse, request)
    try:
        user = User(numtel = args['numtel'], cripto = generate_password_hash(args['cripto']), nome = args['nome'])
        #print(lock)
        #print(args)
        db.session.add(user)
        db.session.commit()
        return jsonify("User added")
    except:
        return jsonify("Unable to add User"), 409

@app.route('/get_user', methods=['GET'])
def get_user():
    if 'numtel' in request.args:
        numtel_user = int(request.args["numtel"])
        user = User.query.filter_by(numtel=numtel_user).first()
        print(user)
        return(jsonify(user.to_dict()))
    return("Error")


@app.route('/add_owner', methods=['PUT'])
@token_required
#@use_args(lock_parse)
def add_owner(current_user):
    try:
        args = parser.parse(owner_parse, request)
        owner = Dono(NUser = current_user.numtel, ID = args['ID'])
        Evento.add_evento(args['ID'], "Dono adicionado: " + args['NUser'] + " por " + owner.NUser)
        new_owner=Dono(NUser = args['NUser'], ID = args['ID'])
        db.session.add(new_owner)
        db.session.commit()
        return jsonify("Owner added")
    except:
        return jsonify("Unable to add Owner"), 409
    


@app.route('/get_owner_keys', methods=['GET'])
@token_required
def get_owner_keys(current_user):
    if 'NUser' in request.args:
        #owneruse = int(request.args["NUser"])
        #fech = Dono.query.filter_by(ID=owneruse).all()
        dono = Dono.query.filter_by(NUser=current_user.numtel).all()
        
        res = [i.fechadura.to_dict() for i in dono]
        c1 = {"fech": res}
        return(jsonify(c1))
    return("Error")

@app.route('/get_key_owners', methods=['GET'])
def get_key_owners():
    if 'ID' in request.args:
        try:
            ident = int(request.args["ID"])
            fech = Dono.query.filter_by(ID=ident).all()
            res = []
            for i in fech:
                entry = {}
                entry["NUser"] = i.NUser
                entry["nome"] = i.user.nome
                res.append(entry)
            c1 = {"owner": res}
            return(jsonify(c1))
            
        except:
            return("Invalid Format"), 400
    return("Error"), 400
        
        



def gerar_code(l):
    password_characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(password_characters) for i in range(l))
    return password

@app.route('/criar_codigo', methods=['PUT'])
@token_required
def put_create_code(current_user):
    args = parser.parse(autent_parse, request)
    qr_codigo = gerar_code(20)
    now = datetime.now()
    autent = Dono.query.filter_by(ID=args['ID'], NUser=current_user.numtel).first()
    if autent is not None:
        code = Autenticacao(ID = args['ID'], NUser = current_user.numtel, Friend = args['Friend'], Codigo = qr_codigo, Momento = now, pin = "")
        Evento.add_evento(args['ID'], "Codigo criado por " + current_user.numtel + " para " + args['Friend'])
        db.session.add(code)
    else:
        Evento.add_evento(args['ID'], "Usuario " + current_user.numtel + " tentou entrar na fechadura")
    db.session.commit()
    
    #evento!!!
    return(jsonify({"code":qr_codigo}))



def compare_time(autent):
    time_mem = autent.Momento
    time_now = datetime.now()
    dif = (time_now-time_mem).total_seconds()
    if dif < 600:
        return True
    else:
        return False

def gerar_PIN():
    PIN_digits = ["0", "1"]
    pin = ''.join(random.choice(PIN_digits) for i in range(5))
    return pin

def enviar_pin(pin):
    return jsonify("Ainda falta fazer")


@app.route('/confirm_codigo', methods=['GET'])
def check_code():
    if 'Codigo' in request.args and 'ID' in request.args and 'Friend' in request.args:
        code = str(request.args["Codigo"])
        ident = int(request.args["ID"])
        fren = str(request.args["Friend"])
        autent = Autenticacao.query.filter_by(Codigo=code, ID=ident, Friend=fren).first()
        if autent is None:
            Evento.add_evento(ident, "Tentativa de codigo falso")
            return jsonify("Nao existe tal codigo para a fechadura")
        if compare_time(autent):
            Evento.add_evento(ident, "Codigo confirmado, pin gerado")
            pin_aut = gerar_PIN()
            enviar_pin(pin_aut)
            #db.update(Autenticacao).where(Autenticacao.Codigo == code and Autenticacao.ID==ident and Autenticacao.Friend==fren).values(pin = pin_aut)
            autent.pin = pin_aut
            db.session.commit()
            #p1 = {"pin":pin_aut, "codigo": code}
            return jsonify(pin_aut)
        else:
            Evento.add_evento(ident, "Codigo expirado usado")
            db.session.delete(autent)
            db.session.commit()
            return jsonify("codigo expirou")




@app.route('/get_pins', methods=['GET'])
@token_required
def pin_no_smartphone(current_user):
    if 'NUser' in request.args:
        NumUser = current_user.numtel
        autent = Autenticacao.query.join(User).filter_by(numtel = NumUser).all()
        if autent is None:
            #evento!!!
            return jsonify("Sem Fechaduras")
        codes = []
        c1 = {"pins": codes}
        for a in autent:
            if compare_time(a):
                #evento!!!
                if a.pin != "":
                    print(a)
                    c = {}
                    c["address"] = a.dono.fechadura.address
                    c["pin"] = a.pin
                    c["tempo"] = a.Momento
                    codes.append(c)
            #else:
            #    a.Autenticacao.delete()
        db.session.commit()  
        return jsonify(c1)
    return(jsonify("Invalid Args"))



@app.route('/add_eventos', methods=['PUT'])
#@use_args(lock_parse)
def add_event():
    try:
        args = parser.parse(event_parse, request)
        evento = Evento(ID = args['ID'], time = datetime.now(), description = args['description'])
        #print(lock)
        #print(args)
        db.session.add(evento)
        db.session.commit()
        return jsonify("Evento adicionado")
    except:
        return jsonify("Unable to add event"), 409

@app.route('/get_eventos', methods=['GET'])
@token_required
def get_event(current_user):
    if 'ID' in request.args:
        id_lock = int(request.args["ID"])
        owner = Dono.query.filter_by(NUser = current_user.numtel, ID = id_lock).first()
        if owner:
            procura = Evento.query.filter_by(ID=id_lock).all()
            eventos = []
            e1 = {"eventos":eventos}
            for a in procura:
                eventos.append(a.to_dict())
            return(jsonify(e1))
        else:
            return(jsonify("NOT YOUR KEY"))   
    return("Error")



@app.errorhandler(422)
@app.errorhandler(400)
def handle_error(err):
    headers = err.data.get("headers", None)
    messages = err.data.get("messages", ["Invalid request."])

    if headers:
        return jsonify({"errors": messages}), err.code, headers
    else:
        return jsonify({"errors": messages}), err.code


if __name__ == "__main__":
    #app.run(host="0.0.0.0", debug = True)
    app.run(threaded=True, port=5000)
