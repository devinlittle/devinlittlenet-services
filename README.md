# PROJECT HAS MOVED TO [HERE](https://github.com/devinlittle/devinlittle-net)

## DevinLittle.net Services


## WARNING, THIS IS BEING HEAVILY EDITED AND MAINTAINED RIGHT NOW

## EXPECT VERY BAD DOCUMENTATION FOR A WHILE WHILE THE PROJECT GROWS

This monorepo provides all of the services DevinLittle.Net uses:
currnetly includes:

* auth service
* gradegetter service
* notification service
* nanopass
* smalltalk

ports used:

* 3000 -- auth service
* 3001 -- gradegetter service
* 3002 -- gradegetter_backend service
* 3003 -- notification_backend service
* 3004 -- nanopass_backend service
* 3005 -- smalltalk_backend service
* 3006 -- service_connector service

# add tech stack

---

# Add roadmap svg here containing:

* document creation + how everything interacts:
  * add mermaid docs

* add tracing and better logging to every crate
* talk about adding smalltalk_messaging
* adding my own error types for gradegetter

## in svg add internal service section:
* add internal mesh network powered by webrtc and grpc
* add service_connector bin which is powered by grpc
* create protobufs
