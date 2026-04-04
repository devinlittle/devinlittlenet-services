# The backend!

## Setup

```bash
cp ./backend/env.template ./.env
# To generate ENCRYPTION_KEY...
echo $(openssl rand -base64 32) >> .env
# Adjust ENV VARS to 
cargo build --release --bin auth_backend
```

# Routes:

| Route                         | Input                                                                                                                                                                             | Function                             |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `/auth/register`              | {<br/>    "username": "devin",<br/>    "password": "password"<br/>}                                                                                                               | Adds user to database                |
| `/auth/login`                 | {<br/> "username": "devin",<br/> "password": "password"<br/>}                                                                                                                     | returns JWT if login info is correct |

