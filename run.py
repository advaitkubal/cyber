import os
import sys

# Change working directory and path to securevault for seamless execution
securevault_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securevault")
sys.path.insert(0, securevault_dir)
os.chdir(securevault_dir)

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
