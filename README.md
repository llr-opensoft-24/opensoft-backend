# Backend
## Local Installation

1. Clone and create, activate virtual environment
```
python3 -m venv venv
source venv/bin/activate
```

2. Install the required libraries
```
pip3 install -r requirements.txt
```

3. Add the required credentials and other variables to `.env` file following the `.env.example` template
```
touch .env
```

4. Start the server as standalone for development purposes
```
python3 app.py
```

5. Start the server for deployment purposes
```
gunicorn -b 0.0.0.0:8000 app:app
```

6. Run the app as a service using systemd in Linux systems
```
sudo nano /etc/systemd/system/flixpedia.service
```

Add the following contents into the above mentioned file:
```
[Unit]
Description=Gunicorn instance for running FlixPedia
After=network.target
[Service]
User={USERNAME_HERE}
Group=www-data
WorkingDirectory={WORKING_DIRECTORY_HERE}
ExecStart={WORKING_DIRECTORY_HERE}/venv/bin/gunicorn -b localhost:8000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
```

Enable the service
```
sudo systemctl daemon-reload
sudo systemctl start flixpedia.service
sudo systemctl enable flixpedia.service
```
