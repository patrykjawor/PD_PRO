Repozytorium dla projektu "<i>System do wymiany plików z wykorzystaniem języka Python</i>".

# Historia zmian widoczna poniżej:
## 04.04.2023
Hashowanie nazw plików z użyciem <a href="https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac" target="blank">pbkdf2_hmac</a> z `salt` unikalnym dla każdego użytkownika (w celu uniknięcia konfliktów dla różnych użytkowników wgrywających pliki o takich samych nazwach).<br/>
Szyfrowanie plików z użyciem <a href="https://cryptography.io/en/latest/fernet/" target="blank">Fernet</a> i prywatnym kluczem przechowywanym po stronie klienta. <br/>
Obliczanie sumy kontrolnej pliku (przed zaszyfrowaniem) i zapisywanie jej w bazie danych.<br/>
Zwracanie listy istniejących plików dla wybranego użytkownika.

## 21.03.2023
Dodano listowanie możliwość widoku plików do pobrania przez zalogowanego użytkownika.<br/>
Dodano możliwość pobrania pojedyńczego pliku wybranego z listbox.<br/>
Wykorzystanie hashlib oraz metody <a href="https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac" target="blank">pbkdf2_hmac</a> do hashowania haseł zapisanych w bazie.
## 17.03.2023
Stworzenie serwera o podstawowej funkcjonalności z logowaniem użytkowników.<br/>
Stworzenie klienta do aplikacji z użyciem biblioteki tkinter.
## 15.03.2023
Testowanie biblioteki kryptograficznej do szyfrowania plików. <br/>
Dodanie aktualnych wymagań środowiska <a href="https://docs.conda.io/en/latest/" target="blank">conda</a> i eksport do `environment.txt/.yml`.
## 14.03.2023
Utworzono repozytorium git.<br/>
Commit początkowy.
