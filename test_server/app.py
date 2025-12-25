from flask import Flask, request

app = Flask(__name__)

# Hardcoded credentials (for testing only)
USERNAME = "admin"
PASSWORD = "password123"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == USERNAME and password == PASSWORD:
            return "✅ Login successful!"
        else:
            return "❌ Invalid username or password", 401

    # Simple HTML login form
    return """
    <h2>Login</h2>
    <form method="POST">
        <label>Username:</label><br>
        <input type="text" name="username"><br><br>

        <label>Password:</label><br>
        <input type="password" name="password"><br><br>

        <input type="submit" value="Login">
    </form>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=True)
