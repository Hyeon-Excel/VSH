import subprocess
import pickle

def run_command(user_input):
    subprocess.run(user_input, shell=True)

def load_data(user_data):
    return pickle.loads(user_data)

def get_user(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    return query
