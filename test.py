import unittest
from unittest.mock import patch
import os
import main

EMAIL = "mail@example.com" # Dummy mail do testów.

class MainTests(unittest.TestCase):
    def setUp(self):
        self.app = main.app.test_client()
        # Czyszczenie bazy i folderów #
        if os.path.exists("users.db"):
            os.remove("users.db")
        for item in [ i for i in os.listdir("uploads") if os.path.isdir(f"uploads/{i}")]:
            os.rmdir(f"uploads/{item}")
        
        for item in [ i for i in os.listdir("flask_session") if os.path.isfile(f"flask_session/{i}")]:
            os.remove(f"flask_session/{item}")
        # Inicjalizacja bazy danych #
        main.init_db()    
        resp = self.app.post("/register", data={'username': 'admin', 'email': f"{EMAIL}",'password': 'e0bD!_x3F'})
        if resp.status_code != 201:
            raise RuntimeError("Dodanie użytkownika nie powiodło się (error code {})!".format(resp.status_code))

        db = main.get_db()
        cursor = db.cursor()
        cursor.execute(
            """
            UPDATE
                users 
            SET 
                two_factory_auth = 442233 
            WHERE 
                username = 'admin'
        """, ()) # Zapisanie klucza OTP do bazy aby ułatwić testowanie aplikacji (normalnie klucz wpisywany byłby z otp.now())
        db.commit()
        cursor.close()
        db.close()

    def test_register_invalid_password(self):
        """Testuje dodanie użytkownika z błędnym hasłem - zbyt krótkie bez wymaganych znaków."""
        response = self.app.post('/register', data={'username': 'testuser', 'email': 'test@example.com', 'password': 'password'})
        self.assertEqual(response.status_code, 400)
    
    def test_register_short_password(self):
        """Hasło zawiera wymagane znaki ale jest zbyt krótkie."""
        response = self.app.post('/register', data={'username': 'testuser', 'email': 'test@example.com', 'password': '!_x3F'})
        self.assertEqual(response.status_code, 400)
    
    def test_register_missing_specialchars_password(self):
        """Hasło jest właściwej długości ale nie zawiera wymaganych znaków."""
        response = self.app.post('/register', data={'username': 'testuser', 'email': 'test@example.com', 'password': 'verylongsimplepassword'})
        self.assertEqual(response.status_code, 400)
    
    def test_register_good_password(self):
        """Poprawne hasło."""
        response = self.app.post('/register', data={'username': 'testuser', 'email': 'test@example.com', 'password': 'e0bD!_x3F'})
        self.assertEqual(response.status_code, 201)

    def test_login(self):
        """Login z właściwymi danymi"""
        response = self.app.post('/login', data={'username': 'admin', 'password': 'e0bD!_x3F'})
        print(response.json)
        self.assertEqual(response.status_code, 200)

    def test_list_files_without_login(self):
        """Próba listowania plików bez uprawnień."""
        response = self.app.get('/files')
        self.assertEqual(response.status_code, 403)

    def test_list_files_with_login_unverified(self):
        """Próba wylistowania plików tylko po zalogowaniu."""
        response = self.app.post("/login", data={'username': 'admin', 'password': 'e0bD!_x3F'})
        if response.status_code != 200:
            raise RuntimeError("Logowanie zakończone niepowodzeniem!")  
        response = self.app.get("/files")
        self.assertEqual(response.status_code, 403)
    
    def test_otp_send_without_login(self):
        """Próba wysłania kodu OTP bez zalogowania"""
        response = self.app.post("/otp") # Nazwa endpointu zgodna z zalecanymi
        self.assertEqual(response.status_code, 400)
    
    def test_otp_send_with_login(self):
        """Próba wysłania kodu OTP po uprzednim zalogowaniu"""
        with self.app as c:
            response = c.post("/login", data={'username': 'admin', 'password': 'e0bD!_x3F'})
            if response.status_code != 200:
                raise RuntimeError("Logowanie zakończone niepowodzeniem!")
            # with c.session_transaction() as sess: # Zmienia sesję
            #     sess['username'] = 'admin'
            response = c.post("/otp", data={"username": "admin"}) # Nazwa endpointu zgodna z zalecanymi
            self.assertEqual(response.status_code, 200)
    
    def test_otp_verify_invalid(self):
        """Próba weryfikacji kodu OTP."""
        with self.app as c:
            with c.session_transaction() as session:
                session['username'] = 'admin'
                session['otp_verified'] = False
            response = c.post("/validate", data={"otp_key": "449068"})
            self.assertEqual(response.status_code, 401)
    
    def test_otp_verify_SQL(self):
        """Próba weryfikacji kodu OTP."""
        with self.app as c:
            with c.session_transaction() as session:
                session['username'] = 'admin'
                session['otp_verified'] = False
            response = c.post("/validate", data={"otp_key": "' OR 1 = 1--"})
            self.assertEqual(response.status_code, 401)

    def test_otp_verify_valid(self):
        """Próba weryfikacji kodu OTP."""

        with self.app as c:
            with c.session_transaction() as session:
                session['username'] = 'admin'
                session['otp_verified'] = False
            response = c.post("/validate", data={"otp_key": "442233"})
            self.assertEqual(response.status_code, 200)
    
    def test_list_files_valid(self):
        with self.app as c:
            if c.post("/login", data={"username": "admin", "password": "e0bD!_x3F"}).status_code != 200:
                raise RuntimeError("Login failed")
            
            with c.session_transaction() as session:
                session['username'] = 'admin'
                session['otp_verified'] = True
            
            response = c.get("/files")
            self.assertEqual(response.status_code, 200)

if __name__== "__main__":
    unittest.main()