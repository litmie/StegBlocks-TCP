import os
import threading

def thread_func1():
    os.system('python server.py')

def thread_func2():
    os.system('python client.py')

a = threading.Thread(target=thread_func1)
a.start()
b = threading.Thread(target=thread_func2)
b.start()
