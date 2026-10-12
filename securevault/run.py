from app import create_app

app = create_app()

if __name__ == "__main__":
    # SECURITY: Debug Disabled - Prevents execution of arbitrary code via Werkzeug interactive debugger
    app.run(host="127.0.0.1", port=5000, debug=False)
