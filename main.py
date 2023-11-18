from flask import Flask, request, jsonify, session, make_response, send_from_directory, abort
from flask_session import Session
from werkzeug.utils import secure_filename
import sqlite3, os, hashlib, re, pyotp, smtplib, configparser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from validate_email_address import validate_email


regex = re.compile(r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-_]).{8,}$") # Regex do sprawdzania hasła

config = configparser.ConfigParser()
if os.path.exists("config"):
    config.read("config")
else:
    config["app"] = {}
    config["app"]["uploads"] = "./"
    config["app"]["session_type"] = 'filesystem'
    config['app']["session_permanent"] = 'False'
    config["email"] = {}
    config["email"]["server"] = "smtp.example.com"
    config["email"]["port"] = '587'
    config["email"]["username"] = "mail@example.com"
    config["email"]["password"] = "password"
    with open("config", "w") as f:
        config.write(f)
    print("Configfile saved to 'config'\nRelaunch application after configuring SMTP parameters.")
    exit(0)

app = Flask(__name__)
app.config['SECRET_KEY'] = b'\xa0\'N\xdb\x96\xb7#\xd1\x92\x06\xc1G?\xc3\x80\xdezek\x01\xafu"$\t3\xd9\xa8\xd6\xb5v\x1d'
app.config['USERS_SALT'] = b'\xfdZ\xcd\x0f\xe3\xe3\xb7\xae\xcc\x9fC\xa5\x1bZ-\x8d \xc5o@Ou\x1e\xed\x16{--a\x1a\xe0Y' # Do hashowania nazw użytkowników
app.config['SESSION_PERMANENT'] = config["app"]["session_permanent"] == 'True' # Czy sesja ma być permanentna
app.config["SESSION_TYPE"] = config["app"]['session_type'] # Rodzaj sesji
app.config["UPLOADS"] = config["app"]["uploads"] # Gdzie mają być przechowywane pliki użytkowników
Session(app)


def get_db():
    db = sqlite3.connect('users.db')
    db.row_factory = sqlite3.Row
    return db

def get_query(query:str, params:tuple):
    db = get_db()
    cursor = db.cursor()
    try:
        result = cursor.execute(query,params).fetchall()
        cursor.close()
        db.close()
        return result
    except Exception as e:
        print(e)
        return None


def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def startup_check(): # Weryfikuje bazę danych z rzeczywistą zawartością folderów.
    users = get_query("SELECT username FROM users", ())
    for user in users:
        userdir = hashlib.pbkdf2_hmac("sha256", user[0].encode('utf-8'), app.config["USERS_SALT"], 10000).hex()
        if not os.path.exists(os.path.join(app.config["UPLOADS"], userdir)):
            try:
                os.mkdir(os.path.join(app.config["UPLOADS"], userdir), 0o744)
            except Exception as e:
                print("Application failed to start:",e)
                exit(-1)

def is_valid(): # https://flask.palletsprojects.com/en/2.2.x/api/#flask.session
    return session.get("username") is not None and session.get('otp_verified') ==  True # and username in session['username']


@app.route('/register', methods=['POST'])
def register():
    username = str(request.form['username'])
    email = request.form['email']
    
    if not bool(username.strip()): # Sprawdzenie nazwy użytkownika - nie może być pusty (w tym '     ')
        abort(400, "Username cannot be empty")
    
    if not bool(email.strip()): # Sprawdzenie maila - nie może być pusty (w tym '     ')
        return abort(400, "Email cannot be empty")
    
    if not validate_email(email): #, verify=True, smtp_timeout=2): # Weryfikuje adres email czekając 2 sekundy na odpowiedź od serwera SMTP.
        abort(400, "Invalid email address")
    
    if not bool(request.form["password"].strip()) or len(request.form["password"]) < 8: # Sprawdzenie długości hasła
        abort(400, "Password should be at least 8 characters")
    
    print("DEBUG:",request.form['password'])

    if not regex.match(request.form['password']): # Sprawdzenie złożoności hasła.
        abort(400, "Password needs to contain one BIG, one small letter, dig1t and spec!al ch@racter")

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            username
        FROM 
            users
        WHERE 
            username = ?
    """, 
        (username,)
    ) # Niestety z sqlite cursor nie pozwala na %(username)s :C
    user = cursor.fetchone()

    if user is not None:
        abort(400, 'Username already exists')

    cursor.execute("""
        SELECT
            email
        FROM
            users
        WHERE
            email = ?
    """,
        (email,)
    )
    user = cursor.fetchone()

    if user is not None:
        return jsonify({'message': 'Email already exists'}), 400
    
    salt = os.urandom(32)
    hash = hashlib.pbkdf2_hmac("sha256", request.form['password'].encode('utf-8'),salt,10000)
    hexhash = (salt+hash).hex()

    userdir = hashlib.pbkdf2_hmac("sha256", username.encode('utf-8'), app.config["USERS_SALT"], 10000).hex()

    magicnumber = os.urandom(32).hex()

    try:
        os.mkdir(os.path.join(app.config["UPLOADS"], userdir), 0o744)
    except Exception as e:
        print("Couldn't create userdir!",e)
        abort(500)

    cursor.execute('INSERT INTO users (username, email, password, magicnumber, two_factory_auth) VALUES (?, ?, ?, ?, ?)',
                   (username, email, hexhash, magicnumber, magicnumber))
    db.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    identifier = request.form.get('username') or request.form.get('email')
    password = request.form['password']

    db = get_db()
    cursor = db.cursor()
    
    passhash =''
    cursor.execute(""" 
        SELECT 
            password
        FROM
            users
        WHERE
            username = ? OR email = ?
        """,  (identifier, identifier))
    result = cursor.fetchone()

    if result is None:
        return jsonify({'message': 'Invalid username or password'}), 401
    else:
        salt = bytes.fromhex(result[0])[:32]
        hash = hashlib.pbkdf2_hmac("sha256", password.encode('utf-8'),salt,10000)
        passhash = (salt+hash).hex()
    
    cursor.execute('SELECT username, magicnumber FROM users WHERE (username = ? OR email = ?) AND password = ?',
                   (identifier, identifier, passhash))
    user = cursor.fetchone()
    if user is None:
        return jsonify({'message': 'Invalid username or password'}), 401
    session['username'] = user[0] # Zapisuje w sesji sprawdza potem w is_valid()
    session['magic_number'] = bytes.fromhex(user[1]) # Zapisuje w sesji 'magic_number' dla użytkownika (używany przy hashowaniu nazw plików itp.)
    session['userdir'] = hashlib.pbkdf2_hmac("sha256", user[0].encode('utf-8'), app.config["USERS_SALT"], 10000).hex()
    session['otp_verified'] = False
    return jsonify({'message': 'Login successful'}), 200

@app.route("/logged", methods=["GET"])
def is_logged_in():
    return jsonify({"value": is_valid()})

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return '', 200

@app.route('/otp', methods=["POST"]) # Update nazwa endpointu zgodna z zaleceniami https://restfulapi.net/resource-naming/
def two_way_auth():
    if session.get('username') is None:
        abort(400, "You need to log in first")
    
    username = request.form['username']
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            email
        FROM 
            users
        WHERE 
            username = ?
    """, 
        (username,)
    )
    user = cursor.fetchone()[0]
    print(user)

    totp = pyotp.TOTP("base32secret3232")
    pyotp_code = totp.now()
    print(pyotp_code)
    cursor.execute('UPDATE users SET two_factory_auth = ? WHERE username = ?', (pyotp_code, username,))
    db.commit()

    session['otp_verified'] = False

    sender_email = config["email"]["username"]
    receiver_email = user
    password = config["email"]["password"]
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = "Your PyOTP Code"
    body = f"Your PyOTP code is {pyotp_code}."
    message.attach(MIMEText(body, "plain"))
    
    with smtplib.SMTP(config["email"]["server"], int(config["email"]["port"])) as server:
        server.starttls()
        server.login(sender_email, password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)
    return "Email sent successfully."

@app.route('/validate', methods=["POST"])
def validate():
    if session.get('username') is None:
        abort(400, "You need to log in first")
    otp = request.form['otp_key']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            two_factory_auth
        FROM 
            users
        WHERE 
            two_factory_auth = ?
    """, 
        (otp,)
    )
    result = cursor.fetchone()
    if result is None:
        return jsonify({'message': 'Invalid OTP CODE'}), 401
    session['otp_verified'] = True
    return jsonify({'message': 'Otp Login successful'}), 200

@app.route('/files', methods=['GET'])
def list_files():
    
    if is_valid(): # Sprawdzenie użytkownika z użyciem flask session
        directory_path = os.path.join(app.config["UPLOADS"], session.get('userdir'))  # podać sciezke ktora bedzie udostepniana
        files = []

        rows = get_query("""
        SELECT 
            filehash,filename,checksum
        FROM 
            files 
        WHERE 
            owner = ?""", (session.get("username"),))
        
        if rows is not None:
            for row in rows:
                # print(row[0], row[1], row[2])
                if os.path.exists(os.path.join(directory_path, row[0])):
                    files.append({"download":row[0],"filename":row[1], "checksum":row[2]})

        # for filename in os.listdir(directory_path): # TODO: Zamienić na sprawdzanie z bazą.
        #     filepath = os.path.join(directory_path, filename)
        #     if os.path.isfile(filepath):
        #         files.append(filename)

        return jsonify({'files': files})
    else:
        abort(403)

@app.route("/upload",methods=["POST"])
def upload():
    if is_valid():
        if 'file' not in request.files:
            abort(400, "Missing file(s)")
        file = request.files['file']
        if file.filename == '':
            abort(400, "No files selected")
        if file:
            hashed_filename = ""
            try:
                metadata = request.args.get('checksum')
                original_filename = secure_filename(file.filename)
                salt = session.get("magic_number")
                hashed_filename = hashlib.pbkdf2_hmac("sha256", original_filename.encode('utf-8'),salt,10000)
                db = get_db()
                cursor = db.cursor()

                result = cursor.execute("""
                SELECT 
                    fileid 
                FROM 
                    files
                WHERE
                    owner = ?
                AND
                    filehash = ?
                """, (session.get('username'), hashed_filename.hex())).fetchone()

                if result is None:
                    cursor.execute("""
                    INSERT INTO 
                        files (owner,filehash,filename,checksum)
                    VALUES
                        (?,?,?,?)
                    """, (session.get('username'), hashed_filename.hex(), original_filename, metadata)) # Do przetestowania.
                else:
                    print("Updating file", original_filename)
                    cursor.execute("""
                    UPDATE 
                        files
                    SET 
                        checksum = ?
                    WHERE 
                        fileid = ?
                    """, (metadata, result[0]))
                
                db.commit()
                cursor.close()

            except Exception as e:
                print(e)
                return jsonify({"message":"An error occured"}), 500
            
            filename = os.path.join(app.config["UPLOADS"], session.get('userdir'), hashed_filename.hex())
            
            try:
                file.save(filename,buffer_size=536_870_912) # Bufor 512MB
                return jsonify({"message": "Upload success!"})
            except Exception as e:
                print(e)
                if hashed_filename != "":
                    db = get_db()
                    cursor = db.cursor()
                    cursor.execute("""
                    DELETE FROM
                        files
                    WHERE
                        filehash = ?
                    """, (hashed_filename.hex(),))
                    db.commit()
                    cursor.close()

                return jsonify({"message":"An error occured"}), 500
        return abort(400)
    else:
        abort(403)

@app.route("/getuser", methods=["GET"])
def getSessionUser():
    if not is_valid():
        abort(403)
    username = session.get('username')
    return jsonify({'username': username})

# ------------------------------------------
# @app.route("/magicnumber", methods=["GET"])
# def getmagicnumber():
#     if is_valid():
#         try:
#             return jsonify({"magic_number":session.get("magic_number").hex()})
#         except Exception:
#             abort(500)
#     else:
#         abort(403)
# ------------------------------------------


@app.route("/download/<path:path>", methods=["GET"])
def download(path):
    if is_valid():
        response = make_response(send_from_directory(os.path.join(app.config["UPLOADS"], session.get('userdir')),path))
        response.headers['Content-Type']= 'application/octet-stream'
        response.headers['Content-Transfer-Encoding'] ='Binary'
        filename = get_query("""
        SELECT
            filename
        FROM
            files
        WHERE
            filehash = ?
        AND
            owner = ?
            """, (path, session.get('username')))
        if filename is not None:
            if len(filename[0]) > 1:
                print("Warning: Multiple files with same hash found!")
            filename = filename[0][0]
        else: # Aby niemożliwe bylo pobranie nie swojego pliku (jeśli posiada go inny użytkownik)
            abort(404)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"' # Załącznik - plik.
        return response
    else: abort(403)


@app.route("/checksum/<path:name>", methods=["GET"])
def get_checksum(name):
    if is_valid():
        checksum = get_query(
            """
            SELECT
                checksum
            FROM
                files
            WHERE 
                filehash = ?
            AND
                owner = ?
            """, (name,session.get("username")))
        if checksum is not None:
            return jsonify({"checksum":checksum[0][0]})
        else:
            abort(404)
    else:
        abort(403)

@app.route("/export", methods=["GET"]) # Eksportowanie bazy danych (tylko do celów testowych!!!)
def exportdb():
    db = get_db()
    cursor = db.cursor()
    result = cursor.execute("""
    SELECT 
        fileid, owner, filehash, filename,  checksum
    FROM 
        files
    """)
    if result is not None:
        with open("files.sql", "w") as f:
            for row in result:
                f.write(f"INSERT INTO files(fileid, owner, filehash, filename,  checksum) VALUES ({row[0]},{row[1]},{row[2]},{row[3]},{row[4]});\n")
        cursor.close()
        return jsonify({'message': 'OK'})
    else:
        return jsonify({'message': 'Nothing to export'})
            

@app.errorhandler(404)
def not_found(e):
    return jsonify({"message": "Not found"}), 404

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"message": "You cannot access this resource"}), 403

@app.errorhandler(400)
def badrequest(e):
    return jsonify({"message":e.description}), 400 # Dodaje opis problemu.

@app.errorhandler(500)
def servererror(e):
    return jsonify({"message":"Something went wrong"}), 500

if __name__ == "__main__":
    init_db()
    startup_check()
    context = ('client.PJ.crt', 'client.PJ.key') # Kontekst SSL do połączenia https
    app.run(host="localhost",port="5000", ssl_context=context ,debug=True,)
    # should_stop = False
    # while not should_stop:
    #    try:
    #        app.run(host="0.0.0.0",port="8000",debug=False,) # Uruchomienie za proxy nginx (produkcyjne)
    #    except Exception as e:
    #        print("Something went wrong:",e)
    #        continue
    #    should_stop = True
    # print("\nApplication finished")
