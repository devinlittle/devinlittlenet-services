# Notifications

listens on port 3003
has routes:
* /ws/{id}

on connection to the websocket user has to send BOOTSTRAP:{JWT_BEARER} if id provided
if id == global then no need to bootstrap

