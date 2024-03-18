# Backend
## Local Installation

1. Clone and create, activate virtual environment
```
python3 -m venv venv
source venv/bin/activate
```

2. install the required libraries
```
pip install -r requirements.txt
```

3. Add the mongo DB_URI credentials to .env file
```
touch .env
```

4. Start the server
```
python app.py
```