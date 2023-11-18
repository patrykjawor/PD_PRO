================================
Flask server documentation
================================

This documentation provides an overview and reference for the Flask server application.

Installation
------------

To install the Flask application, follow these steps:

1. Clone the repository::

   $ git clone <repository-url>

2. Install the required dependencies::

   $ pip install -r requirements.txt

Configuration
-------------

The Flask application can be configured using the following environment variables:

- ``SECRET_KEY``: Secret key used for session encryption.
- ``SESSION_PERMANENT``: Whether the session should be permanent.
- ``SESSION_TYPE``: Type of session storage.
- ``UPLOADS``: Path to the directory where files will be uploaded.

Database
--------

The Flask application uses an SQLite database for user and file management. The database file is ``users.db``, and the schema is defined in ``schema.sql``. To initialize the database, run the following command:

.. code-block:: shell

   $ flask init-db

Routes
------

The Flask application exposes the following routes:

POST /register
~~~~~~~~~~~~~~

Registers a new user with the provided username, email, and password.

Request body parameters:

- ``username``: User's username.
- ``email``: User's email address.
- ``password``: User's password.

POST /login
~~~~~~~~~~~

Logs in a user with the provided username or email and password.

Request body parameters:

- ``username`` or ``email``: User's username or email address.
- ``password``: User's password.

GET /logged
~~~~~~~~~~~

Checks if a user is logged in.

Returns a JSON response indicating whether the user is logged in.

POST /logout
~~~~~~~~~~~~

Logs out the currently logged-in user.

POST /2FA
~~~~~~~~~~~

Enables two-factor authentication for the specified user.

Request body parameters:

- ``username``: User's username.

Sends an email with a PyOTP code to the user's email address.

POST /validate
~~~~~~~~~~~~~~~

Validates a PyOTP code for two-factor authentication.

Request body parameters:

- ``otp_key``: The PyOTP code to validate.

GET /files
~~~~~~~~~~~~~~~

Lists all files uploaded by the currently logged-in user.

Returns a JSON response with information about each file, including the filename and checksum.

POST /upload
~~~~~~~~~~~~~~~

Uploads a file for the currently logged-in user.

Request parameters:

- ``file``: The file to upload.

Query parameters:

- ``checksum``: The checksum metadata for the file.

GET /getuser
~~~~~~~~~~~~

Retrieves the username of the currently logged-in user.

Returns a JSON response with the username.

GET /download/<path:path>
~~~~~~~~~~~~~~~~~~~~~~~~~~

Downloads a file with the specified path for the currently logged-in user.

GET /checksum/<path:name>
~~~~~~~~~~~~~~~~~~~~~~~~~

Retrieves the checksum of a file with the specified name for the currently logged-in user.

Returns a JSON response with the checksum.

GET /export
~~~~~~~~~~~

Exports the database to a file named ``files.sql``.

Error Handling
--------------

The Flask application handles the following error cases:

- ``404 Not Found``: The requested resource is not found.
- ``403 Forbidden``: Access to the resource is forbidden.
- ``400 Bad Request``: The request is malformed or missing required parameters.
- ``500 Internal Server Error``: An unexpected error occurred.

Development Server
------------------

To run the Flask application in development mode, use the following command:

.. code-block:: shell

   $ flask run

The application will be available at http://localhost:5000.

Production Deployment
---------------------

To deploy the Flask application in a production environment, follow these steps:

1. Configure a web server (e.g., Nginx) to proxy requests to the Flask application.
2. Use a production-grade WSGI server to serve the Flask application.