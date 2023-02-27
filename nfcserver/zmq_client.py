import zmq

context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5555")

message = "hmochida       0       1677449578"
socket.send_string(message)
response = socket.recv_string()

print(f"Received response: {response}")

socket.close()
context.term()
