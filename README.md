# BSK project - Tool for Emulating the Qualified Electronic Signature

The main goal of the application is to implement document-signing functionality
(at least *.pdf and *.txt files), file encryption and key generation. <p>

The project is developed for the subject Security of
Computer Systems at Gdansk University of Technology. <p>

## Project structure

### Document signing app

- `mainApp/main.py` - the application startup file
- `mainApp/BSK_window.py` - the application interface
- `mainApp/gui_functions.py` - implementation of methods called by interface buttons
- `mainApp/requirements.txt` - required packages for the app

### Key generator app

- `keyGenerator/main.py` - the application startup file
- `keyGenerator/GenerateKeysApp.py` - the application interface and the implementation of the methods
- `keyGenerator/requirements.txt` - required packages for the app
