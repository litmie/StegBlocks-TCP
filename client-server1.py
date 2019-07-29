import os
import threading

def thread_func1():
    os.system('python server1.py')

def thread_func2():
    os.system('python client1.py')

def thread_func3():
    os.system('python client2.py')

def thread_func4():
    os.system('python client3.py')

a = threading.Thread(target=thread_func1)
a.start()
b = threading.Thread(target=thread_func2)
b.start()
c = threading.Thread(target=thread_func3)
c.start()
d = threading.Thread(target=thread_func4)
d.start()
