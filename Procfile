# normal web servers can't run Python applications, so a special type of server was created (WSGI) to run our Flask app.  Essentially, a WSGI server standardises the language and protocols between our Python Flask application and the host server.
# There are many web servers to choose from, but the most popular is gunicorn.
# Our hosting provider will call Gunicorn to run our code

# Steps to deploy a Flask app with Gunicorn and Procfile:
#
# 1. Add 'gunicorn' to your requirements.txt file so it gets installed on your server.
#    Example line in requirements.txt:
#    gunicorn==<version>
#
# 2. Create a Procfile in your project root directory. This file tells the platform (like Heroku) how to run your app.
#    The Procfile should have no extension and must be named exactly 'Procfile'.
#
# 3. Inside the Procfile, specify the command to start your app using Gunicorn:
#    web: gunicorn main:app
#    - 'web:' means this is a web process.
#    - 'main' is the name of your Python file (main.py).
#    - 'app' is the Flask app variable inside main.py.
#
# Example Procfile content:
# web: gunicorn main:app
web: gunicorn main:app
