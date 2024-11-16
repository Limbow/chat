
from enum import Enum
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'root'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/chat_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

class RoleEnum(Enum):
    user = 'user'
    staff = 'staff'
    admin = 'admin'

# Modelos de base de datos
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.Enum(RoleEnum), default=RoleEnum.user)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role not in [RoleEnum.staff, RoleEnum.admin]:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/change_role/<int:user_id>', methods=['POST'], endpoint='change_role')
@login_required
@staff_required
def change_role(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("Usuario no encontrado")
        return redirect(url_for('admin_page'))

    new_role = request.form['role']
    
    user.role = RoleEnum[new_role]
    db.session.commit()
    
    flash(f"Rol de {user.username} cambiado a {new_role}.")
    return redirect(url_for('admin_page'))


@app.route('/admin', methods=['GET'], endpoint='admin_page')
@login_required
@staff_required
def admin():
    users = User.query.all()
    return render_template('admin.html', users=users, user_role=current_user.role.value, cUser = current_user)


@app.route('/check_username', methods=['POST'])
def check_username():
    username = request.json.get('username')
    existing_user = User.query.filter_by(username=username).first()
    return jsonify({'exists': existing_user is not None})


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        
        role = request.form.get('role', 'user')
        
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Usuario registrado con éxito', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        receiver_username = request.form['receiver']
        content = request.form['content']
        receiver = User.query.filter_by(username=receiver_username).first()

        if receiver:
            message = Message(sender_id=current_user.id, receiver_id=receiver.id, content=content)
            db.session.add(message)
            db.session.commit()
            
            flash('Mensaje enviado con éxito', 'success')
        else:
            flash('El usuario destinatario no existe', 'error')
            
        return redirect(url_for('inbox'))
    
    return render_template('send_message.html')

@app.route('/inbox', methods=['GET', 'POST'])
@login_required
def inbox():
    users_with_conversations = db.session.query(User).join(Message, (Message.sender_id == User.id) | (Message.receiver_id == User.id)) \
        .filter((Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)) \
        .distinct().filter(User.id != current_user.id).all()

    selected_user = None
    messages = []
    if request.method == 'POST':
        selected_user_id = request.form.get('selected_user')
        response_content = request.form.get('response_content')
        
        if selected_user_id:
            selected_user = User.query.get(selected_user_id)
            
            messages = Message.query.filter(
                (Message.sender_id == current_user.id) & (Message.receiver_id == selected_user.id) |
                (Message.receiver_id == current_user.id) & (Message.sender_id == selected_user.id)
            ).order_by(Message.timestamp).all()
            
            
            if response_content:
                response_message = Message(
                    sender_id=current_user.id,
                    receiver_id=selected_user.id,
                    content=response_content
                )
                db.session.add(response_message)
                db.session.commit()
                flash('Mensaje de respuesta enviado con éxito.', 'success')
                return redirect(url_for('inbox'))
              
        else:
            flash('Por favor, selecciona un usuario para ver la conversación.')

    return render_template('inbox.html', users=users_with_conversations, selected_user=selected_user, messages=messages)
    
    #received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    #return render_template('inbox.html', messages=received_messages)


@app.route('/')
@login_required
def index():
    return render_template('index.html')

if __name__ == '__main__':
    #db.create_all()
    app.run(debug=True)
